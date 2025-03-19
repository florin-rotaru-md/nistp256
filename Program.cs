using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace nistp256
{
    [MemoryDiagnoser]
    public class ECDSABenchmark
    {
        private byte[] data;
        private ECDsa systemECDsa;
        private AsymmetricCipherKeyPair bouncyCastleKeyPair;
        private ECDsaSigner bouncyCastleSigner;
        private ECPrivateKeyParameters bouncyCastlePrivateKey;
        private ECPublicKeyParameters bouncyCastlePublicKey;

        [Params("nistP256", "nistP384", "nistP521")]
        public string CurveName;

        [GlobalSetup]
        public void Setup()
        {
            data = new byte[32];
            RandomNumberGenerator.Fill(data);

            // System.Security.Cryptography setup
            systemECDsa = ECDsa.Create(CurveName switch
            {
                "nistP384" => ECCurve.NamedCurves.nistP384,
                "nistP521" => ECCurve.NamedCurves.nistP521,
                _ => ECCurve.NamedCurves.nistP256
            });

            // BouncyCastle setup
            var curve = SecNamedCurves.GetByName(CurveName);
            var domain = new ECDomainParameters(curve);
            var generator = new ECKeyPairGenerator();
            var keyGenParams = new ECKeyGenerationParameters(domain, new SecureRandom());
            generator.Init(keyGenParams);
            bouncyCastleKeyPair = generator.GenerateKeyPair();
            bouncyCastlePrivateKey = (ECPrivateKeyParameters)bouncyCastleKeyPair.Private;
            bouncyCastlePublicKey = (ECPublicKeyParameters)bouncyCastleKeyPair.Public;
            bouncyCastleSigner = new ECDsaSigner();
            bouncyCastleSigner.Init(true, bouncyCastlePrivateKey);
        }

        [Benchmark]
        public byte[] SystemECDSASign() => systemECDsa.SignData(data, HashAlgorithmName.SHA256);

        [Benchmark]
        public bool SystemECDSAVerify()
        {
            var signature = systemECDsa.SignData(data, HashAlgorithmName.SHA256);
            return systemECDsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
        }

        [Benchmark]
        public BigInteger[] BouncyCastleSign() => bouncyCastleSigner.GenerateSignature(data);

        [Benchmark]
        public bool BouncyCastleVerify()
        {
            var signature = bouncyCastleSigner.GenerateSignature(data);
            var verifier = new ECDsaSigner();
            verifier.Init(false, bouncyCastlePublicKey);
            return verifier.VerifySignature(data, signature[0], signature[1]);
        }

        [Benchmark]
        public void SystemECDSAParallelSign()
        {
            Parallel.For(0, 1000, _ => systemECDsa.SignData(data, HashAlgorithmName.SHA256));
        }

        [Benchmark]
        public void BouncyCastleParallelSign()
        {
            Parallel.For(0, 1000, _ => bouncyCastleSigner.GenerateSignature(data));
        }
    }

    class Program
    {
        static void Main() => BenchmarkRunner.Run<ECDSABenchmark>();
    }
}