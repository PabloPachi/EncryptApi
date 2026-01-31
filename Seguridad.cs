using System.Security.Cryptography;
using System.Text;

public static class Seguridad
{
    private static int passwordIterations = 2;
    public static string Decrypt(string encryptedText)
    {
        if (encryptedText == null)
        {
            return null;
        }
        if (string.IsNullOrEmpty(encryptedText))
        {
            return "";
        }
        byte[] bytes = Encoding.UTF8.GetBytes("word");
        byte[] buffer3 = Decrypt(Convert.FromBase64String(encryptedText), SHA256.Create().ComputeHash(bytes));
        return Encoding.UTF8.GetString(buffer3);
    }
    private static byte[] Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
    {
        byte[] buffer = null;
        byte[] salt = new byte[] { 9, 2, 8, 3, 7, 4, 6, 5 };
        using (MemoryStream stream = new MemoryStream())
        {
            using (RijndaelManaged managed = new RijndaelManaged())
            {
                Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(passwordBytes, salt, 0x3e8);
                managed.KeySize = 0x100;
                managed.BlockSize = 0x80;
                managed.Key = bytes.GetBytes(managed.KeySize / 8);
                managed.IV = bytes.GetBytes(managed.BlockSize / 8);
                managed.Mode = CipherMode.CBC;
                using (CryptoStream stream2 = new CryptoStream(stream, managed.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    stream2.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                    stream2.Close();
                }
                buffer = stream.ToArray();
            }
        }
        return buffer;
    }

    public static string Encrypt(string plainText)
    {
        if (plainText == null)
        {
            return null;
        }
        if (string.IsNullOrEmpty(plainText))
        {
            return "";
        }
        byte[] bytes = Encoding.UTF8.GetBytes("word");
        return Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(plainText), SHA256.Create().ComputeHash(bytes)));
    }

    private static byte[] Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
    {
        byte[] buffer = null;
        byte[] salt = new byte[] { 9, 2, 8, 3, 7, 4, 6, 5 };
        using (MemoryStream stream = new MemoryStream())
        {
            using (RijndaelManaged managed = new RijndaelManaged())
            {
                Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(passwordBytes, salt, 0x3e8);
                managed.KeySize = 0x100;
                managed.BlockSize = 0x80;
                managed.Key = bytes.GetBytes(managed.KeySize / 8);
                managed.IV = bytes.GetBytes(managed.BlockSize / 8);
                managed.Mode = CipherMode.CBC;
                using (CryptoStream stream2 = new CryptoStream(stream, managed.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    stream2.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                    stream2.Close();
                }
                buffer = stream.ToArray();
            }
        }
        return buffer;
    }
    public static string Encripta(string plainText)
    {
        if (plainText == null)
        {
            return null;
        }
        byte[] bytes = Encoding.UTF8.GetBytes("algo");
        return Convert.ToBase64String(Encripta(Encoding.UTF8.GetBytes(plainText), SHA256.Create().ComputeHash(bytes)));
    }
    public static string EncriptaBase64(string texto)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(texto);
        return Convert.ToBase64String(bytes);
    }
    public static string DecriptaBase64(string texto)
    {
        byte[] bytes = Convert.FromBase64String(texto);
        return Encoding.UTF8.GetString(bytes);
    }

    private static byte[] Encripta(byte[] bytesToBeEncrypted, byte[] passwordBytes)
    {
        byte[] buffer = null;
        byte[] salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        using (MemoryStream stream = new MemoryStream())
        {
            using (RijndaelManaged managed = new RijndaelManaged())
            {
                Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(passwordBytes, salt, 0x3e8);
                managed.KeySize = 0x100;
                managed.BlockSize = 0x80;
                managed.Key = bytes.GetBytes(managed.KeySize / 8);
                managed.IV = bytes.GetBytes(managed.BlockSize / 8);
                managed.Mode = CipherMode.CBC;
                using (CryptoStream stream2 = new CryptoStream(stream, managed.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    stream2.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                    stream2.Close();
                }
                buffer = stream.ToArray();
            }
        }
        return buffer;
    }
    public static string GetHash(string strPassword, string salt, HashAlgorithm algoritmo)
    {
        string str2;
        try
        {
            str2 = Convert.ToBase64String(new PasswordDeriveBytes(strPassword, Encoding.UTF8.GetBytes(salt), algoritmo.ToString(), passwordIterations).GetBytes(0x40));
        }
        catch (Exception exception)
        {
            throw new Exception("Error al obtener el Hash de SegurinetEncryptionHelper con el algoritmo " + algoritmo.ToString() + ", " + exception.Message, exception);
        }
        return str2;
    }

    public enum HashAlgorithm
    {
        MD5,
        SHA1,
        SHA256,
        SHA384,
        SHA512,
        HMACSHA1
    }
}