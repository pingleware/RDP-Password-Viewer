# ============================================================
#  RDP 密码查看器  (RDP Password Viewer)
#  - 扫描本机保存的远程桌面(RDP)服务器地址与密码
#  - 凭据管理器 / Credentials 文件 / .rdp 文件 / 连接历史
#  - 纯本地运行, 零外部依赖 (加密调用系统 bcrypt.dll)
#  用法:  双击 “启动.bat”  或  powershell -File 本文件 [-NoGui]
# ============================================================
param(
    [switch]$NoGui,
    [string]$LoginPassword = ""
)

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# C# 核心: 凭据枚举 + DPAPI 手工解密 (masterkey + blob)
# ------------------------------------------------------------
$csSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace RdpVaultNs
{
    public class RdpRow
    {
        public string Server { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string DisplayPwd { get; set; }
        public string SavedAt { get; set; }
        public string Source { get; set; }
        public string Status { get; set; }
        public string RealTarget { get; set; }
    }

    public static class RdpVault
    {
        // ---------------- log ----------------
        public static List<string> Log = new List<string>();
        static void L(string s) { Log.Add(s); }

        // ---------------- pinvoke ----------------
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CREDENTIAL
        {
            public int Flags;
            public int Type;
            public string TargetName;
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }
        [DllImport("advapi32.dll", EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredEnumerate(string filter, int flags, out int count, out IntPtr pCreds);
        [DllImport("advapi32.dll")]
        static extern void CredFree(IntPtr p);

        [StructLayout(LayoutKind.Sequential)]
        public struct DATA_BLOB { public int cbData; public IntPtr pbData; }
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CryptUnprotectData(ref DATA_BLOB dataIn, string descr, IntPtr entropy, IntPtr res, IntPtr prompt, int flags, ref DATA_BLOB dataOut);
        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr h);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        static extern int BCryptOpenAlgorithmProvider(out IntPtr hAlg, string algId, IntPtr implementation, int flags);
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        static extern int BCryptSetProperty(IntPtr hObject, string prop, byte[] value, int cbInput, int flags);
        [DllImport("bcrypt.dll")]
        static extern int BCryptGenerateSymmetricKey(IntPtr hAlg, out IntPtr hKey, IntPtr keyObject, int cbKeyObject, byte[] secret, int cbSecret, int flags);
        [DllImport("bcrypt.dll")]
        static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, IntPtr padding, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);
        [DllImport("bcrypt.dll")]
        static extern int BCryptDestroyKey(IntPtr hKey);
        [DllImport("bcrypt.dll")]
        static extern int BCryptCloseAlgorithmProvider(IntPtr hAlg, int flags);

        // ---------------- 哈希工具 ----------------
        static byte[] Sha1(byte[] d) { using (SHA1 h = SHA1.Create()) return h.ComputeHash(d); }
        static byte[] Hmac(System.Security.Cryptography.HMAC h, byte[] key, byte[] msg)
        { h.Key = key; byte[] r = h.ComputeHash(msg); h.Clear(); return r; }
        static byte[] HmacSha1(byte[] key, byte[] msg) { using (HMACSHA1 h = new HMACSHA1()) return Hmac(h, key, msg); }
        static byte[] HmacSha512(byte[] key, byte[] msg) { using (HMACSHA512 h = new HMACSHA512()) return Hmac(h, key, msg); }

        // hash 算法信息: 0x8004=SHA1(20,64) 0x8009=HMAC 0x800E=SHA512(64,128)
        // hashModule: true=SHA512 false=SHA1
        static void HashInfo(int alg, out int hashLen, out int blockSize, out bool sha512)
        {
            if (alg == 0x800E) { hashLen = 64; blockSize = 128; sha512 = true; }
            else { hashLen = 20; blockSize = 64; sha512 = false; }  // 0x8004 / 0x8009
        }

        // ---------------- MD4 (用于 NT 派生 prekey) ----------------
        static uint rol(uint x, int n) { return (x << n) | (x >> (32 - n)); }
        public static byte[] MD4(byte[] input)
        {
            uint[] digest = new uint[4];
            digest[0] = 0x67452301u; digest[1] = 0xefcdab89u; digest[2] = 0x98badcfeu; digest[3] = 0x10325476u;
            int len = input.Length;
            int padded = ((len + 8) / 64 + 1) * 64;
            byte[] msg = new byte[padded];
            Array.Copy(input, msg, len);
            msg[len] = 0x80;
            ulong bitLen = (ulong)len * 8;
            for (int i = 0; i < 8; i++) msg[padded - 8 + i] = (byte)(bitLen >> (8 * i));
            int[] r1s = new int[] { 3, 7, 11, 19 };
            int[] r2idx = new int[] { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
            int[] r2s = new int[] { 3, 5, 9, 13 };
            int[] r3idx = new int[] { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 };
            int[] r3s = new int[] { 3, 9, 11, 15 };
            for (int off = 0; off < padded; off += 64)
            {
                uint[] x = new uint[16];
                for (int i = 0; i < 16; i++) x[i] = BitConverter.ToUInt32(msg, off + i * 4);
                uint a = digest[0], b = digest[1], c = digest[2], d = digest[3];
                for (int i = 0; i < 16; i++)
                {
                    uint f = (b & c) | (~b & d);
                    uint t = a + f + x[i];
                    a = d; d = c; c = b; b = rol(t, r1s[i % 4]);
                }
                for (int i = 0; i < 16; i++)
                {
                    uint g = (b & c) | (b & d) | (c & d);
                    uint t = a + g + 0x5A827999u + x[r2idx[i]];
                    a = d; d = c; c = b; b = rol(t, r2s[i % 4]);
                }
                for (int i = 0; i < 16; i++)
                {
                    uint h = b ^ c ^ d;
                    uint t = a + h + 0x6ED9EBA1u + x[r3idx[i]];
                    a = d; d = c; c = b; b = rol(t, r3s[i % 4]);
                }
                digest[0] += a; digest[1] += b; digest[2] += c; digest[3] += d;
            }
            byte[] outb = new byte[16];
            for (int i = 0; i < 4; i++) Array.Copy(BitConverter.GetBytes(digest[i]), 0, outb, i * 4, 4);
            return outb;
        }

        // ---------------- 对称解密 (bcrypt, CBC, 无padding) ----------------
        static byte[] SymDecrypt(string algName, byte[] key, byte[] iv, byte[] data)
        {
            IntPtr hAlg;
            int st = BCryptOpenAlgorithmProvider(out hAlg, algName, IntPtr.Zero, 0);
            if (st != 0) throw new Exception("BCryptOpenAlgorithmProvider " + algName + " err " + st);
            try
            {
                byte[] chain = Encoding.Unicode.GetBytes("ChainingModeCBC\0");
                st = BCryptSetProperty(hAlg, "ChainingMode", chain, chain.Length, 0);
                if (st != 0) throw new Exception("BCryptSetProperty err " + st);
                IntPtr hKey;
                st = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
                if (st != 0) throw new Exception("BCryptGenerateSymmetricKey err " + st);
                try
                {
                    byte[] ivCopy = (byte[])iv.Clone();
                    byte[] outb = new byte[data.Length];
                    int cb;
                    st = BCryptDecrypt(hKey, data, data.Length, IntPtr.Zero, ivCopy, ivCopy.Length, outb, outb.Length, out cb, 0);
                    if (st != 0) throw new Exception("BCryptDecrypt err " + st);
                    byte[] r = new byte[cb]; Array.Copy(outb, r, cb); return r;
                }
                finally { BCryptDestroyKey(hKey); }
            }
            finally { BCryptCloseAlgorithmProvider(hAlg, 0); }
        }

        static byte[] XorBytes(byte[] a, byte[] b)
        {
            byte[] r = new byte[a.Length];
            for (int i = 0; i < a.Length; i++) r[i] = (byte)(a[i] ^ b[i]);
            return r;
        }
        static byte[] FixParity(byte[] k)
        {
            byte[] r = new byte[k.Length];
            for (int i = 0; i < k.Length; i++)
            {
                byte b = k[i]; int ones = 0;
                for (int j = 0; j < 7; j++) if (((b >> (7 - j)) & 1) == 1) ones++;
                byte low = (byte)(b & 0xfe);
                r[i] = (ones % 2 == 0) ? (byte)(low | 1) : low;
            }
            return r;
        }
        static byte[] Pkcs7Unpad(byte[] d, int bs)
        {
            if (d == null || d.Length == 0) return d;
            int n = d[d.Length - 1];
            if (n < 1 || n > bs || n > d.Length) return d; // 无有效padding, 原样返回
            for (int i = d.Length - n; i < d.Length; i++) if (d[i] != n) return d;
            byte[] r = new byte[d.Length - n]; Array.Copy(d, r, r.Length); return r;
        }

        // ---------------- prekey 派生 ----------------
        static List<byte[]> DerivePrekeys(string sid, string password)
        {
            List<byte[]> list = new List<byte[]>();
            byte[] sid16 = Encoding.Unicode.GetBytes(sid + "\0");
            byte[] pw16 = Encoding.Unicode.GetBytes(password);
            byte[] sha1pw = Sha1(pw16);
            list.Add(HmacSha1(sha1pw, sid16));           // key1 (本地/微软账户主用)
            list.Add(sha1pw);                             // key4
            byte[] nt = MD4(pw16);
            if (nt != null) list.Add(HmacSha1(nt, sid16)); // key2 (NT 派生)
            return list;
        }

        // ---------------- masterkey 文件解析与解密 ----------------
        class MkSection
        {
            public byte[] salt; public int iterations; public int hashAlg; public int cryptoAlg; public byte[] data;
        }
        class MkFile
        {
            public string guid; public MkSection masterkey; public MkSection backupkey;
        }

        static MkFile ParseMasterKeyFile(byte[] raw)
        {
            if (raw.Length < 124) return null;
            MkFile f = new MkFile();
            f.guid = Encoding.Unicode.GetString(raw, 12, 72).Trim().Trim('{', '}');
            long mkLen = BitConverter.ToInt64(raw, 96);
            long bkLen = BitConverter.ToInt64(raw, 104);
            long chLen = BitConverter.ToInt64(raw, 112);
            long dkLen = BitConverter.ToInt64(raw, 120);
            int pos = 128;
            if (mkLen > 0 && pos + mkLen <= raw.Length)
            {
                f.masterkey = ParseMkSection(raw, pos, (int)mkLen); pos += (int)mkLen;
            }
            if (bkLen > 0 && pos + bkLen <= raw.Length)
            {
                f.backupkey = ParseMkSection(raw, pos, (int)bkLen); pos += (int)bkLen;
            }
            return f;
        }
        static MkSection ParseMkSection(byte[] raw, int pos, int len)
        {
            int end = pos + len;
            MkSection s = new MkSection();
            s.salt = new byte[16]; Array.Copy(raw, pos + 4, s.salt, 0, 16);
            s.iterations = BitConverter.ToInt32(raw, pos + 20);
            s.hashAlg = BitConverter.ToInt32(raw, pos + 24);
            s.cryptoAlg = BitConverter.ToInt32(raw, pos + 28);
            s.data = new byte[end - (pos + 32)]; Array.Copy(raw, pos + 32, s.data, 0, s.data.Length);
            return s;
        }

        static byte[] DecryptMkSection(MkSection s, byte[] prekey)
        {
            try
            {
                int hashLen, blockSize; bool sha512;
                HashInfo(s.hashAlg, out hashLen, out blockSize, out sha512);
                // masterkey KDF: CALG_HMAC(0x8009) 特殊用 SHA1, 其余按表
                bool kdfSha512 = sha512 && s.hashAlg != 0x8009;
                int keyLen, ivLen; string algName;
                CryptoInfo(s.cryptoAlg, out keyLen, out ivLen, out algName);
                int need = keyLen + ivLen;
                byte[] temp = new byte[0];
                int counter = 1;
                while (temp.Length < need)
                {
                    byte[] u = new byte[20];
                    Array.Copy(s.salt, 0, u, 0, 16);
                    u[16] = (byte)(counter >> 24); u[17] = (byte)(counter >> 16);
                    u[18] = (byte)(counter >> 8); u[19] = (byte)counter;
                    byte[] derived = kdfSha512 ? HmacSha512(prekey, u) : HmacSha1(prekey, u);
                    for (int i = 0; i < s.iterations - 1; i++)
                    {
                        byte[] actual = kdfSha512 ? HmacSha512(prekey, derived) : HmacSha1(prekey, derived);
                        derived = XorBytes(derived, actual);
                    }
                    byte[] nt2 = new byte[temp.Length + derived.Length];
                    Array.Copy(temp, nt2, temp.Length); Array.Copy(derived, 0, nt2, temp.Length, derived.Length);
                    temp = nt2;
                    counter++;
                }
                byte[] cryptKey = new byte[keyLen]; Array.Copy(temp, 0, cryptKey, 0, keyLen);
                byte[] iv = new byte[ivLen]; Array.Copy(temp, keyLen, iv, 0, ivLen);
                byte[] clear = SymDecrypt(algName, cryptKey, iv, s.data);
                if (clear.Length < 16 + hashLen + 64) return null;
                byte[] keyDec = new byte[64]; Array.Copy(clear, clear.Length - 64, keyDec, 0, 64);
                byte[] hmacSalt = new byte[16]; Array.Copy(clear, 0, hmacSalt, 0, 16);
                byte[] hmacRes = new byte[hashLen]; Array.Copy(clear, 16, hmacRes, 0, hashLen);
                byte[] hmacKey = kdfSha512 ? HmacSha512(prekey, hmacSalt) : HmacSha1(prekey, hmacSalt);
                byte[] calc = kdfSha512 ? HmacSha512(hmacKey, keyDec) : HmacSha1(hmacKey, keyDec);
                for (int i = 0; i < hashLen; i++) if (calc[i] != hmacRes[i]) return null;
                return keyDec;
            }
            catch { return null; }
        }

        static void CryptoInfo(int alg, out int keyLen, out int ivLen, out string algName)
        {
            if (alg == 0x6610) { keyLen = 32; ivLen = 16; algName = "AES"; }
            else if (alg == 0x6603) { keyLen = 24; ivLen = 8; algName = "3DES"; }
            else if (alg == 0x6611) { keyLen = 16; ivLen = 16; algName = "AES"; }   // AES-128
            else if (alg == 0x6612) { keyLen = 24; ivLen = 16; algName = "AES"; }   // AES-192
            else { keyLen = 24; ivLen = 8; algName = "3DES"; }
        }

        // ---------------- DPAPI blob 解析与解密 ----------------
        class BlobInfo
        {
            public string mkGuid; public byte[] salt; public byte[] hmacKey; public byte[] toSign;
            public byte[] data; public byte[] signature; public int hashAlg; public int cryptoAlg;
        }
        static BlobInfo ParseBlob(byte[] d)
        {
            BlobInfo b = new BlobInfo();
            int pos = 0;
            pos += 4;                     // version
            pos += 16;                    // provider guid
            int signStart = pos;
            pos += 4;                     // masterkey version
            byte[] g = new byte[16]; Array.Copy(d, pos, g, 0, 16); pos += 16;
            b.mkGuid = new Guid(g).ToString("D");
            pos += 4;                     // flags
            int descLen = BitConverter.ToInt32(d, pos); pos += 4 + descLen;
            b.cryptoAlg = BitConverter.ToInt32(d, pos); pos += 4;
            pos += 4;                     // crypto_algorithm_length
            int saltLen = BitConverter.ToInt32(d, pos); pos += 4;
            b.salt = new byte[saltLen]; Array.Copy(d, pos, b.salt, 0, saltLen); pos += saltLen;
            int hkLen = BitConverter.ToInt32(d, pos); pos += 4;
            pos += hkLen;                 // HMAC_key 字段 (通常为空)
            b.hashAlg = BitConverter.ToInt32(d, pos); pos += 4;
            pos += 4;                     // hash_algorithm_length
            int hmacLen = BitConverter.ToInt32(d, pos); pos += 4;
            b.hmacKey = new byte[hmacLen]; Array.Copy(d, pos, b.hmacKey, 0, hmacLen); pos += hmacLen;
            int dataLen = BitConverter.ToInt32(d, pos); pos += 4;
            b.data = new byte[dataLen]; Array.Copy(d, pos, b.data, 0, dataLen); pos += dataLen;
            int signEnd = pos;
            b.toSign = new byte[signEnd - signStart]; Array.Copy(d, signStart, b.toSign, 0, b.toSign.Length);
            int sigLen = BitConverter.ToInt32(d, pos); pos += 4;
            b.signature = new byte[sigLen]; Array.Copy(d, pos, b.signature, 0, sigLen);
            return b;
        }

        static byte[] DecryptBlob(BlobInfo b, byte[] masterkey, byte[] entropy)
        {
            try
            {
                int hashLen, hashBlock; bool sha512;
                HashInfo(b.hashAlg, out hashLen, out hashBlock, out sha512);
                // blob 路径按表 (CALG_HMAC→SHA512)
                int keyLen, ivLen; string algName;
                CryptoInfo(b.cryptoAlg, out keyLen, out ivLen, out algName);

                byte[] keyHash = Sha1(masterkey);
                byte[] saltEnt = new byte[b.salt.Length + (entropy == null ? 0 : entropy.Length)];
                Array.Copy(b.salt, saltEnt, b.salt.Length);
                if (entropy != null) Array.Copy(entropy, 0, saltEnt, b.salt.Length, entropy.Length);
                byte[] sessionKey = sha512 ? HmacSha512(keyHash, saltEnt) : HmacSha1(keyHash, saltEnt);
                byte[] derived;
                if (sessionKey.Length > hashBlock)
                    derived = sha512 ? HmacSha512(sessionKey, new byte[0]) : HmacSha1(sessionKey, new byte[0]);
                else
                    derived = sessionKey;
                if (derived.Length < keyLen)
                {
                    byte[] padded = new byte[hashBlock];
                    Array.Copy(derived, padded, derived.Length);
                    byte[] ipad = new byte[hashBlock], opad = new byte[hashBlock];
                    for (int i = 0; i < hashBlock; i++) { ipad[i] = (byte)(padded[i] ^ 0x36); opad[i] = (byte)(padded[i] ^ 0x5c); }
                    byte[] h1 = sha512 ? Sha512(ipad) : Sha1(ipad);
                    byte[] h2 = sha512 ? Sha512(opad) : Sha1(opad);
                    byte[] dk = new byte[h1.Length + h2.Length];
                    Array.Copy(h1, dk, h1.Length); Array.Copy(h2, 0, dk, h1.Length, h2.Length);
                    derived = FixParity(dk);
                }
                byte[] key = new byte[keyLen]; Array.Copy(derived, 0, key, 0, keyLen);
                byte[] iv = new byte[ivLen];
                byte[] raw = SymDecrypt(algName, key, iv, b.data);
                byte[] cleartext = Pkcs7Unpad(raw, ivLen);

                // HMAC 校验 (两种算法任一通过即可)
                // hmac1 = H(opad2 || H(ipad2 || HMACField) || entropy || toSign)
                byte[] kh2 = new byte[hashBlock];
                Array.Copy(keyHash, kh2, keyHash.Length);
                byte[] ipad2 = new byte[hashBlock], opad2 = new byte[hashBlock];
                for (int i = 0; i < hashBlock; i++) { ipad2[i] = (byte)(kh2[i] ^ 0x36); opad2[i] = (byte)(kh2[i] ^ 0x5c); }
                byte[] innerHash = sha512 ? Sha512Cat(ipad2, b.hmacKey) : Sha1Cat(ipad2, b.hmacKey);
                byte[] outerParts = new byte[innerHash.Length + (entropy == null ? 0 : entropy.Length) + b.toSign.Length];
                {
                    int o = 0;
                    Array.Copy(innerHash, 0, outerParts, o, innerHash.Length); o += innerHash.Length;
                    if (entropy != null) { Array.Copy(entropy, 0, outerParts, o, entropy.Length); o += entropy.Length; }
                    Array.Copy(b.toSign, 0, outerParts, o, b.toSign.Length);
                }
                byte[] hmac1 = sha512 ? Sha512Cat(opad2, outerParts) : Sha1Cat(opad2, outerParts);
                if (BytesEq(hmac1, b.signature)) return cleartext;
                // hmac3 = HMAC(keyHash, HMACField || entropy || toSign)
                byte[] msg3 = new byte[b.hmacKey.Length + (entropy == null ? 0 : entropy.Length) + b.toSign.Length];
                {
                    int o = 0;
                    Array.Copy(b.hmacKey, 0, msg3, o, b.hmacKey.Length); o += b.hmacKey.Length;
                    if (entropy != null) { Array.Copy(entropy, 0, msg3, o, entropy.Length); o += entropy.Length; }
                    Array.Copy(b.toSign, 0, msg3, o, b.toSign.Length);
                }
                byte[] hmac3 = sha512 ? HmacSha512(keyHash, msg3) : HmacSha1(keyHash, msg3);
                if (BytesEq(hmac3, b.signature)) return cleartext;
                return null;
            }
            catch { return null; }
        }

        static byte[] Sha512(byte[] d) { using (SHA512 h = SHA512.Create()) return h.ComputeHash(d); }
        static byte[] Sha1Cat(byte[] a, byte[] b)
        {
            using (SHA1 h = SHA1.Create())
            {
                h.TransformBlock(a, 0, a.Length, null, 0);
                h.TransformFinalBlock(b, 0, b.Length);
                return h.Hash;
            }
        }
        static byte[] Sha512Cat(byte[] a, byte[] b)
        {
            using (SHA512 h = SHA512.Create())
            {
                h.TransformBlock(a, 0, a.Length, null, 0);
                h.TransformFinalBlock(b, 0, b.Length);
                return h.Hash;
            }
        }
        static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant(); }
        static bool BytesEq(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        // ---------------- CryptUnprotectData 包装 (.rdp 文件 blob 用) ----------------
        public static byte[] CryptUnprotect(byte[] data, byte[] entropy)
        {
            DATA_BLOB din = new DATA_BLOB();
            din.cbData = data.Length;
            din.pbData = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, din.pbData, data.Length);
            IntPtr entPtr = IntPtr.Zero;
            DATA_BLOB dout = new DATA_BLOB();
            try
            {
                if (entropy != null && entropy.Length > 0)
                {
                    DATA_BLOB ent = new DATA_BLOB();
                    ent.cbData = entropy.Length;
                    ent.pbData = Marshal.AllocHGlobal(entropy.Length);
                    Marshal.Copy(entropy, 0, ent.pbData, entropy.Length);
                    entPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(DATA_BLOB)));
                    Marshal.StructureToPtr(ent, entPtr, false);
                }
                if (!CryptUnprotectData(ref din, null, entPtr, IntPtr.Zero, IntPtr.Zero, 0, ref dout))
                    return null;
                byte[] r = new byte[dout.cbData];
                Marshal.Copy(dout.pbData, r, 0, dout.cbData);
                return r;
            }
            finally
            {
                LocalFree(din.pbData);
                if (entPtr != IntPtr.Zero) LocalFree(entPtr);
                if (dout.pbData != IntPtr.Zero) LocalFree(dout.pbData);
            }
        }

        // ---------------- CREDENTIAL_BLOB 解析 ----------------
        class CredPlain
        {
            public string target, alias, description, unk3, username, unk4;
        }
        static CredPlain ParseCredBlob(byte[] d)
        {
            CredPlain c = new CredPlain();
            int pos = 4 + 4 + 4;      // flags,size,unk0
            pos += 4;                 // type
            pos += 4;                 // flags2
            pos += 8;                 // last_written
            pos += 4 + 4 + 4;         // unk1,persist,attrcount
            pos += 8;                 // unk2
            c.target = ReadWStr(d, ref pos);
            c.alias = ReadWStr(d, ref pos);
            c.description = ReadWStr(d, ref pos);
            c.unk3 = ReadWStr(d, ref pos);
            c.username = ReadWStr(d, ref pos);
            c.unk4 = ReadWStr(d, ref pos);
            return c;
        }
        static string ReadWStr(byte[] d, ref int pos)
        {
            if (pos + 4 > d.Length) { pos = d.Length; return ""; }
            int len = BitConverter.ToInt32(d, pos); pos += 4;
            if (len <= 0 || pos + len > d.Length) { return ""; }
            string s = Encoding.Unicode.GetString(d, pos, len).TrimEnd('\0');
            pos += len;
            return s;
        }

        // ---------------- 凭据枚举 ----------------
        public class CredEntryInfo
        {
            public string Target, UserName; public int Type; public DateTime LastWritten; public byte[] Blob;
        }
        public static List<CredEntryInfo> EnumCreds()
        {
            List<CredEntryInfo> list = new List<CredEntryInfo>();
            int count; IntPtr pCreds;
            if (!CredEnumerate("TERMSRV*", 0, out count, out pCreds)) return list;
            try
            {
                for (int i = 0; i < count; i++)
                {
                    IntPtr pCred = Marshal.ReadIntPtr(pCreds, i * IntPtr.Size);
                    CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(pCred, typeof(CREDENTIAL));
                    CredEntryInfo e = new CredEntryInfo();
                    e.Target = cred.TargetName;
                    e.UserName = cred.UserName;
                    e.Type = cred.Type;
                    long ft = ((long)cred.LastWritten.dwHighDateTime << 32) + (uint)cred.LastWritten.dwLowDateTime;
                    try { e.LastWritten = DateTime.FromFileTime(ft); } catch { e.LastWritten = DateTime.MinValue; }
                    if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                    {
                        e.Blob = new byte[cred.CredentialBlobSize];
                        Marshal.Copy(cred.CredentialBlob, e.Blob, 0, cred.CredentialBlobSize);
                    }
                    list.Add(e);
                }
            }
            finally { CredFree(pCreds); }
            return list;
        }

        // ---------------- 主扫描 ----------------
        static Dictionary<string, byte[]> _masterkeys = new Dictionary<string, byte[]>();

        static Dictionary<string, byte[]> LoadMasterkeys(List<byte[]> prekeys, string sid)
        {
            Dictionary<string, byte[]> result = new Dictionary<string, byte[]>();
            string protectRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", "Protect");
            if (!Directory.Exists(protectRoot)) return result;
            // 候选密码: 用户输入 + 空密码
            List<byte[]> all = new List<byte[]>(prekeys);
            foreach (byte[] k in DerivePrekeys(sid, "")) if (!ContainsKey(all, k)) all.Add(k);
            string[] sidDirs = Directory.GetDirectories(protectRoot);
            foreach (string sidDir in sidDirs)
            {
                if (Path.GetFileName(sidDir).Equals("CREDHIST", StringComparison.OrdinalIgnoreCase)) continue;
                string[] files = Directory.GetFiles(sidDir);
                foreach (string f in files)
                {
                    string name = Path.GetFileName(f);
                    if (name.Equals("Preferred", StringComparison.OrdinalIgnoreCase)) continue;
                    try
                    {
                        MkFile mf = ParseMasterKeyFile(File.ReadAllBytes(f));
                        if (mf == null || mf.masterkey == null) continue;
                        foreach (byte[] pk in all)
                        {
                            byte[] key = DecryptMkSection(mf.masterkey, pk);
                            if (key != null)
                            {
                                string g = NormalizeGuid(mf.guid);
                                if (!result.ContainsKey(g)) result.Add(g, key);
                                L("  主密钥解密成功: " + g);
                                break;
                            }
                        }
                    }
                    catch (Exception ex) { L("  主密钥文件失败 " + name + ": " + ex.Message); }
                }
            }
            return result;
        }
        static bool ContainsKey(List<byte[]> list, byte[] k)
        {
            foreach (byte[] x in list) if (BytesEq(x, k)) return true;
            return false;
        }
        static string NormalizeGuid(string s)
        {
            try { return new Guid(s.Trim('{', '}')).ToString("D"); }
            catch { return s; }
        }

        public static List<RdpRow> Scan(string password)
        {
            Log.Clear();
            List<RdpRow> rows = new List<RdpRow>();
            string sid = WindowsIdentity.GetCurrent().User.Value;
            string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string roamApp = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            // 1) 凭据管理器条目
            List<CredEntryInfo> entries = EnumCreds();
            L("凭据管理器: 找到 " + entries.Count + " 条 TERMSRV 记录");

            // 2) 主密钥
            List<byte[]> prekeys = DerivePrekeys(sid, password == null ? "" : password);
            _masterkeys = LoadMasterkeys(prekeys, sid);
            L("主密钥: 成功解密 " + _masterkeys.Count + " 个");
            bool mkOk = _masterkeys.Count > 0;

            // 3) 凭据条目 -> 行 (generic 明文密码立即展示)
            Dictionary<string, RdpRow> byServer = new Dictionary<string, RdpRow>();
            foreach (CredEntryInfo e in entries)
            {
                RdpRow r = new RdpRow();
                string t = e.Target ?? "";
                string server = t.StartsWith("TERMSRV/", StringComparison.OrdinalIgnoreCase) ? t.Substring(8) : t;
                r.Server = server;
                r.Username = e.UserName ?? "";
                r.SavedAt = e.LastWritten == DateTime.MinValue ? "" : e.LastWritten.ToString("yyyy-MM-dd HH:mm");
                r.Source = e.Type == 1 ? "凭据管理器(通用)" : "凭据管理器(域)";
                r.RealTarget = t;
                if (e.Type == 1 && e.Blob != null && e.Blob.Length > 0)
                {
                    r.Password = Encoding.Unicode.GetString(e.Blob).TrimEnd('\0');
                    r.Status = "OK";
                }
                else
                {
                    r.Password = "";
                    r.Status = mkOk ? "OK" : "LOCK";
                }
                if (!byServer.ContainsKey(server)) byServer[server] = r;
                rows.Add(r);
            }

            // 4) Credentials 目录文件解密
            string[] credDirs = new string[] {
                Path.Combine(localApp, "Microsoft", "Credentials"),
                Path.Combine(roamApp, "Microsoft", "Credentials")
            };
            int fileDec = 0;
            foreach (string dir in credDirs)
            {
                if (!Directory.Exists(dir)) continue;
                foreach (string f in Directory.GetFiles(dir))
                {
                    try
                    {
                        byte[] raw = File.ReadAllBytes(f);
                        if (raw.Length < 16) continue;
                        int ver = BitConverter.ToInt32(raw, 0);
                        int size = BitConverter.ToInt32(raw, 4);
                        if (ver != 1 || size <= 0 || 12 + size > raw.Length) continue;
                        byte[] blobData = new byte[size];
                        Array.Copy(raw, 12, blobData, 0, size);
                        BlobInfo bi = ParseBlob(blobData);
                        byte[] mk = null;
                        if (bi != null && _masterkeys.TryGetValue(bi.mkGuid, out mk))
                        {
                            byte[] plain = DecryptBlob(bi, mk, null);
                            if (plain != null && plain.Length > 8)
                            {
                                CredPlain cp = ParseCredBlob(plain);
                                string t = cp.target ?? "";
                                if (t.IndexOf("TERMSRV/", StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    int idx = t.IndexOf('=');
                                    string server = idx >= 0 ? t.Substring(idx + 1) : t;
                                    server = server.StartsWith("TERMSRV/", StringComparison.OrdinalIgnoreCase) ? server.Substring(8) : server;
                                    string realPwd = cp.unk4;
                                    RdpRow existing = null;
                                    if (byServer.TryGetValue(server, out existing))
                                    {
                                        if (realPwd.Length > 0) { existing.Password = realPwd; existing.Status = "OK"; }
                                        if (existing.Username.Length == 0 && cp.username.Length > 0) existing.Username = cp.username;
                                        existing.RealTarget = t;
                                    }
                                    else
                                    {
                                        RdpRow r = new RdpRow();
                                        r.Server = server; r.Username = cp.username; r.Password = realPwd;
                                        r.Source = "凭据文件";
                                        r.Status = "OK"; r.RealTarget = t;
                                        r.SavedAt = new FileInfo(f).LastWriteTime.ToString("yyyy-MM-dd HH:mm");
                                        byServer[server] = r; rows.Add(r);
                                    }
                                    fileDec++;
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            L("凭据文件: 成功解密 " + fileDec + " 个 TERMSRV blob");

            // 5) 状态整理
            foreach (RdpRow r in rows)
            {
                if (r.Status == "OK" && r.Password.Length > 0) r.Status = "OK";
                else if (r.Status == "OK") r.Status = "EMPTY";
                else r.Status = "LOCK";
                r.DisplayPwd = r.Password;
            }
            return rows;
        }

        // ---------------- .rdp 文件 blob 解密 ----------------
        public static string DecryptRdpPasswordBlob(byte[] blob)
        {
            try
            {
                byte[] p = CryptUnprotect(blob, null);
                if (p != null && p.Length > 0)
                    return Encoding.Unicode.GetString(p).TrimEnd('\0');
            }
            catch { }
            // 回退: 手工解密 (SYSTEM 标记 blob)
            try
            {
                if (_masterkeys.Count == 0) return null;
                BlobInfo bi = ParseBlob(blob);
                if (bi == null) return null;
                byte[] mk;
                if (!_masterkeys.TryGetValue(bi.mkGuid, out mk)) return null;
                byte[] plain = DecryptBlob(bi, mk, null);
                if (plain == null) return null;
                return Encoding.Unicode.GetString(plain).TrimEnd('\0');
            }
            catch { return null; }
        }
    }
}
'@

Add-Type -TypeDefinition $csSource -Language CSharp

# ------------------------------------------------------------
# 扫描封装 (PS 侧: 端口历史 + .rdp 文件 + 装饰)
# ------------------------------------------------------------
function Get-MruMap {
    $map = @{}
    $base = 'HKCU:\Software\Microsoft\Terminal Server Client\Servers'
    if (Test-Path $base) {
        try {
            Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
                $name = $_.PSChildName
                if ($name -match '^(.+):\d+$') {
                    $map[$matches[1]] = $name          # IP -> IP:port
                } else {
                    $map[$name] = $name
                }
            }
        } catch {}
    }
    return $map
}

function Get-RdpFiles {
    $found = @()
    $dirs = @(
        [Environment]::GetFolderPath('MyDocuments'),
        [Environment]::GetFolderPath('Desktop'),
        $env:USERPROFILE
    )
    foreach ($d in $dirs) {
        if (-not $d -or -not (Test-Path $d)) { continue }
        try {
            $found += Get-ChildItem -Path $d -Filter *.rdp -File -ErrorAction SilentlyContinue
            try { $found += Get-ChildItem -Path $d -Filter *.rdp -File -Recurse -Depth 2 -ErrorAction SilentlyContinue } catch {}
        } catch {}
    }
    return $found | Sort-Object FullName -Unique
}

function Invoke-FullScan {
    param([string]$Password = "")

    $rows = [RdpVaultNs.RdpVault]::Scan($Password)
    $mru = Get-MruMap

    # 装饰端口
    foreach ($r in $rows) {
        if ($mru.ContainsKey($r.Server) -and $mru[$r.Server] -ne $r.Server) {
            $r.Server = $mru[$r.Server]
        }
    }

    # .rdp 文件
    $rdpFiles = Get-RdpFiles
    foreach ($f in $rdpFiles) {
        try {
            $addr = $null; $user = $null; $pwHex = $null
            foreach ($line in [IO.File]::ReadAllLines($f.FullName)) {
                if ($line -match '^full address:s:(.+)$') { $addr = $Matches[1].Trim() }
                elseif ($line -match '^username:s:(.+)$') { $user = $Matches[1].Trim() }
                elseif ($line -match '^password 51:b:([0-9a-fA-F\s]+)$') { $pwHex = $Matches[1] -replace '\s','' }
            }
            if (-not $addr) { continue }
            $dup = $rows | Where-Object { $_.Server -eq $addr }
            $row = $dup | Select-Object -First 1
            if (-not $row) {
                $row = New-Object RdpVaultNs.RdpRow
                $row.Server = $addr
                $row.Username = $user
                $row.Password = ''
                $row.SavedAt = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                $row.Source = '.rdp 文件'
                $row.Status = 'EMPTY'
                $rows += $row
            } else {
                if (-not $row.Source) { $row.Source = '.rdp 文件' }
            }
            if ($pwHex -and $pwHex.Length -gt 0 -and -not $row.Password) {
                try {
                    $blob = New-Object byte[] ($pwHex.Length / 2)
                    for ($i = 0; $i -lt $blob.Length; $i++) { $blob[$i] = [Convert]::ToByte($pwHex.Substring($i*2, 2), 16) }
                    $pw = [RdpVaultNs.RdpVault]::DecryptRdpPasswordBlob($blob)
                    if ($pw) { $row.Password = $pw; $row.Status = 'OK'; $row.Source = '.rdp 文件' }
                } catch {}
            }
        } catch {}
    }

    # 仅历史记录 (未保存密码)
    foreach ($k in $mru.Keys) {
        $disp = $mru[$k]
        if (-not ($rows | Where-Object { $_.Server -eq $disp })) {
            $row = New-Object RdpVaultNs.RdpRow
            $row.Server = $disp; $row.Username = ''; $row.Password = ''
            $row.Source = '连接历史'; $row.Status = 'HIST'
            $rows += $row
        }
    }

    foreach ($r in $rows) { $r.DisplayPwd = $r.Password }
    return $rows
}

# ------------------------------------------------------------
# 命令行模式
# ------------------------------------------------------------
if ($NoGui) {
    $rows = Invoke-FullScan -Password $LoginPassword
    $pretty = $rows | ForEach-Object {
        $icon = switch ($_.Status) { 'OK' {'[解密成功]'} 'LOCK' {'[需密码]'} 'HIST' {'[仅历史]'} default {'[无密码]' } }
        [PSCustomObject]@{
            服务器 = $_.Server; 用户名 = $_.Username
            密码 = if ($_.Status -eq 'OK') { $_.Password } else { '-' }
            状态 = $icon; 保存时间 = $_.SavedAt; 来源 = $_.Source
        }
    }
    $pretty | Format-Table -AutoSize | Out-String -Width 200
    Write-Host ("`n--- 日志 ---")
    [RdpVaultNs.RdpVault]::Log | ForEach-Object { Write-Host $_ }
    exit 0
}

# ------------------------------------------------------------
# WPF 界面
# ------------------------------------------------------------
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="RDP 密码查看器" Height="660" Width="1020"
        WindowStartupLocation="CenterScreen" Background="#FF16161E"
        FontFamily="Microsoft YaHei UI" UseLayoutRounding="True">
    <Window.Resources>
        <Style x:Key="Btn" TargetType="Button">
            <Setter Property="Background" Value="#FF89B4FA"/>
            <Setter Property="Foreground" Value="#FF1E1E2E"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="Padding" Value="16,8"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" CornerRadius="8" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#FFB4BEFE"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#FF585B70"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="BtnGhost" TargetType="Button" BasedOn="{StaticResource Btn}">
            <Setter Property="Background" Value="#FF313244"/>
            <Setter Property="Foreground" Value="#FFCDD6F4"/>
        </Style>
        <Style x:Key="ColHeader" TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="#FF313244"/>
            <Setter Property="Foreground" Value="#FFBAC2DE"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Padding" Value="10,8"/>
            <Setter Property="BorderBrush" Value="#FF45475A"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
        </Style>
        <Style x:Key="Cell" TargetType="TextBlock">
            <Setter Property="Foreground" Value="#FFCDD6F4"/>
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="Margin" Value="6,4"/>
        </Style>
    </Window.Resources>
    <DockPanel>
        <Border DockPanel.Dock="Top" Background="#FF181825" Padding="22,16,22,12">
            <StackPanel>
                <TextBlock Text="🔐 RDP 密码查看器" FontSize="22" FontWeight="Bold" Foreground="#FF89B4FA"/>
                <TextBlock Text="一键找回本机远程桌面保存的服务器地址与密码 · 全程本地解密，不上传任何数据"
                           FontSize="12" Foreground="#FF6C7086" Margin="2,4,0,0"/>
            </StackPanel>
        </Border>
        <Border DockPanel.Dock="Top" Background="#FF11111B" Padding="22,10,22,10">
            <DockPanel>
                <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="登录密码(可选)" Foreground="#FFA6ADC8" FontSize="12" VerticalAlignment="Center" Margin="0,0,6,0"/>
                    <PasswordBox Name="PwdBox" Width="180" Height="32" VerticalContentAlignment="Center"
                                 Background="#FF1E1E2E" Foreground="#FFCDD6F4" BorderBrush="#FF45475A" BorderThickness="1" Padding="6,0"
                                 ToolTip="域凭据解密失败时，输入当前 Windows 登录密码（锁屏密码，不是 PIN）再点扫描"/>
                    <Button Name="BtnScan" Content="🔍 开始扫描" Style="{StaticResource Btn}" Margin="10,0,0,0" MinWidth="110" Height="32"/>
                </StackPanel>
                <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                    <Button Name="BtnExport" Content="📤 导出 CSV" Style="{StaticResource BtnGhost}" Height="32" MinWidth="96"/>
                    <Button Name="BtnToggle" Content="🙈 隐藏密码" Style="{StaticResource BtnGhost}" Margin="8,0,0,0" Height="32" MinWidth="96"/>
                </StackPanel>
            </DockPanel>
        </Border>
        <Border DockPanel.Dock="Bottom" Background="#FF181825" Padding="14,8">
            <TextBlock Name="StatusText" Text="就绪 — 点击「开始扫描」" Foreground="#FFA6ADC8" FontSize="12"/>
        </Border>
        <DataGrid Name="Grid" Margin="14,10,14,10" AutoGenerateColumns="False"
                  Background="#FF11111B" RowBackground="#FF1E1E2E" AlternatingRowBackground="#FF232334"
                  Foreground="#FFCDD6F4" HorizontalGridLinesBrush="#FF313244" VerticalGridLinesBrush="#FF313244"
                  BorderBrush="#FF45475A" BorderThickness="1"
                  HeadersVisibility="Column" CanUserAddRows="False" IsReadOnly="True"
                  SelectionMode="Extended" RowHeight="38" FontSize="13" ColumnHeaderStyle="{StaticResource ColHeader}">
            <DataGrid.Columns>
                <DataGridTextColumn Header="服务器" Binding="{Binding Server}" Width="200">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock" BasedOn="{StaticResource Cell}">
                            <Setter Property="Foreground" Value="#FF89B4FA"/>
                            <Setter Property="FontWeight" Value="SemiBold"/>
                        </Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
                <DataGridTextColumn Header="用户名" Binding="{Binding Username}" Width="170" ElementStyle="{StaticResource Cell}"/>
                <DataGridTextColumn Header="密码" Binding="{Binding DisplayPwd}" Width="*">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock" BasedOn="{StaticResource Cell}">
                            <Setter Property="FontFamily" Value="Consolas"/>
                            <Setter Property="Foreground" Value="#FFA6E3A1"/>
                        </Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
                <DataGridTextColumn Header="保存时间" Binding="{Binding SavedAt}" Width="130" ElementStyle="{StaticResource Cell}"/>
                <DataGridTextColumn Header="来源" Binding="{Binding Source}" Width="120" ElementStyle="{StaticResource Cell}"/>
                <DataGridTextColumn Header="状态" Binding="{Binding Status}" Width="90">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock" BasedOn="{StaticResource Cell}">
                            <Style.Triggers>
                                <DataTrigger Binding="{Binding Status}" Value="OK">
                                    <Setter Property="Text" Value="✅ 已解密"/>
                                    <Setter Property="Foreground" Value="#FFA6E3A1"/>
                                </DataTrigger>
                                <DataTrigger Binding="{Binding Status}" Value="LOCK">
                                    <Setter Property="Text" Value="🔒 需密码"/>
                                    <Setter Property="Foreground" Value="#FFF9E2AF"/>
                                </DataTrigger>
                                <DataTrigger Binding="{Binding Status}" Value="HIST">
                                    <Setter Property="Text" Value="🕘 仅历史"/>
                                    <Setter Property="Foreground" Value="#FF6C7086"/>
                                </DataTrigger>
                                <DataTrigger Binding="{Binding Status}" Value="EMPTY">
                                    <Setter Property="Text" Value="—"/>
                                    <Setter Property="Foreground" Value="#FF6C7086"/>
                                </DataTrigger>
                            </Style.Triggers>
                        </Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
                <DataGridTemplateColumn Header="操作" Width="80">
                    <DataGridTemplateColumn.CellTemplate>
                        <DataTemplate>
                            <Button Content="📋 复制" FontSize="12" Padding="8,4" Margin="4" Cursor="Hand"
                                    Background="#FF313244" Foreground="#FFCDD6F4" BorderThickness="0">
                                <Button.Template>
                                    <ControlTemplate TargetType="Button">
                                        <Border x:Name="Bd" Background="#FF313244" CornerRadius="6" Padding="8,5">
                                            <ContentPresenter HorizontalAlignment="Center"/>
                                        </Border>
                                        <ControlTemplate.Triggers>
                                            <Trigger Property="IsMouseOver" Value="True">
                                                <Setter Property="Background" Value="#FF45475A" TargetName="Bd"/>
                                            </Trigger>
                                        </ControlTemplate.Triggers>
                                    </ControlTemplate>
                                </Button.Template>
                            </Button>
                        </DataTemplate>
                    </DataGridTemplateColumn.CellTemplate>
                </DataGridTemplateColumn>
            </DataGrid.Columns>
        </DataGrid>
    </DockPanel>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$grid      = $window.FindName('Grid')
$btnScan   = $window.FindName('BtnScan')
$btnExport = $window.FindName('BtnExport')
$btnToggle = $window.FindName('BtnToggle')
$pwdBox    = $window.FindName('PwdBox')
$status    = $window.FindName('StatusText')

$script:allRows = @()
$script:showPwd = $true

function Set-Status([string]$t) { $status.Text = $t }

function Do-Scan {
    $btnScan.IsEnabled = $false
    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    Set-Status "扫描中…"
    try {
        $pw = $pwdBox.Password
        $script:allRows = Invoke-FullScan -Password $pw
        $ok  = @($script:allRows | Where-Object { $_.Status -eq 'OK' }).Count
        $lock= @($script:allRows | Where-Object { $_.Status -eq 'LOCK' }).Count
        $grid.ItemsSource = $script:allRows
        if ($lock -gt 0 -and $ok -eq 0) {
            Set-Status ("找到 {0} 条记录，但域凭据未解开 — 请在右上角输入 Windows 登录密码后重新扫描" -f $script:allRows.Count)
            $pwdBox.Focus()
        } elseif ($lock -gt 0) {
            Set-Status ("完成：{0} 条记录，{1} 条已解密，{2} 条需登录密码" -f $script:allRows.Count, $ok, $lock)
        } else {
            Set-Status ("完成：共 {0} 条记录，{1} 条成功解密 ✅" -f $script:allRows.Count, $ok)
        }
    } catch {
        Set-Status ("扫描出错: " + $_.Exception.Message)
    } finally {
        $window.Cursor = $null
        $btnScan.IsEnabled = $true
    }
}

$btnScan.Add_Click({ Do-Scan })
$pwdBox.Add_KeyDown({
    param($s, $e)
    if ($e.Key -eq 'Enter') { Do-Scan }
})

$grid.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler]{
    param($sender, $e)
    $row = $e.OriginalSource.DataContext
    if ($row -and $row.Password) {
        Set-Clipboard -Value $row.Password
        $btn = $e.OriginalSource
        $old = $btn.Content; $btn.Content = '✔ 已复制'
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds(900)
        $timer.Add_Tick({ $btn.Content = $old; $timer.Stop() })
        $timer.Start()
        Set-Status ("已复制 {0} 的密码到剪贴板" -f $row.Server)
    }
})

$grid.Add_MouseDoubleClick({
    param($sender, $e)
    $row = $grid.SelectedItem
    if ($row -and $row.Password) {
        Set-Clipboard -Value $row.Password
        Set-Status ("已复制 {0} 的密码到剪贴板" -f $row.Server)
    }
})

$btnToggle.Add_Click({
    $script:showPwd = -not $script:showPwd
    foreach ($r in $script:allRows) {
        $r.DisplayPwd = if ($script:showPwd -and $r.Password) { $r.Password } elseif ($r.Password) { ('•' * [Math]::Min($r.Password.Length, 16)) } else { '' }
    }
    $grid.ItemsSource = $null
    $grid.ItemsSource = $script:allRows
    $btnToggle.Content = if ($script:showPwd) { '🙈 隐藏密码' } else { '👁 显示密码' }
})

$btnExport.Add_Click({
    if (-not $script:allRows -or $script:allRows.Count -eq 0) { [System.Windows.MessageBox]::Show("没有可导出的数据，请先扫描。","提示"); return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = "CSV 文件 (*.csv)|*.csv"
    $dlg.FileName = "RDP密码_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".csv"
    if ($dlg.ShowDialog()) {
        $lines = @("服务器,用户名,密码,保存时间,来源,状态")
        foreach ($r in $script:allRows) {
            $pw = if ($r.Status -eq 'OK') { $r.Password } else { '' }
            $lines += ('"{0}","{1}","{2}","{3}","{4}","{5}"' -f $r.Server, $r.Username, $pw, $r.SavedAt, $r.Source, $r.Status)
        }
        [IO.File]::WriteAllLines($dlg.FileName, $lines, (New-Object System.Text.UTF8Encoding $true))
        Set-Status ("已导出到 " + $dlg.FileName)
    }
})

$window.Add_Loaded({ Do-Scan })
[void]$window.ShowDialog()
