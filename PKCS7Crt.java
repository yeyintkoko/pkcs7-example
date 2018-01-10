
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;

// --------------------------------------------
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.CMSProcessable;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Collection;
import java.util.Iterator;
// --------------------------------


import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class PKCS7Crt {

  private static final String PATH_TO_CRT = "openssl-cert/selfsigned.crt";

  public PKCS7Crt() {

  }
  /** Write the certificate file with a digital signature. */
  private void writeSignatureBlock(CMSTypedData data, X509Certificate publicKey,
          PrivateKey privateKey)
                      throws IOException,
                      CertificateEncodingException,
                      OperatorCreationException,
                      CMSException {

      ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
      certList.add(publicKey);
      JcaCertStore certs = new JcaCertStore(certList);

      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
      ContentSigner sha1Signer = new JcaContentSignerBuilder(
                                     "SHA1with" + privateKey.getAlgorithm())
                                 .build(privateKey);
      gen.addSignerInfoGenerator(
          new JcaSignerInfoGeneratorBuilder(
              new JcaDigestCalculatorProviderBuilder()
              .build())
          .setDirectSignature(true)
          .build(sha1Signer, publicKey));
      gen.addCertificates(certs);
      CMSSignedData sigData = gen.generate(data, false);

      ASN1InputStream asn1 = new ASN1InputStream(sigData.getEncoded());
      DEROutputStream dos = new DEROutputStream(mOutputJar);
      dos.writeObject(asn1.readObject());

      dos.flush();
      dos.close();
      asn1.close();
  }


  /**
 *
 * Check the signature is correct, conform to plain data and the certificate chain is ok
 *
 * @throws CertPathValidatorException
 * @throws CertificateException
 * @throws InvalidAlgorithmParameterException
 *
 */

@SuppressWarnings("unchecked")
public boolean verify(byte[] data, byte[] signedData, X509Certificate[] caCertificates,
        Provider provider) throws NoSuchProviderException, NoSuchAlgorithmException, CertStoreException, CMSException, InvalidAlgorithmParameterException, CertificateException, CertPathValidatorException
{
    CMSProcessableByteArray processableByteArray = new CMSProcessableByteArray(data);

    CMSSignedData cmsSignedData = new CMSSignedData(processableByteArray, signedData);

    CertStore certs = cmsSignedData.getCertificatesAndCRLs("Collection", provider);

    SignerInformationStore signers = cmsSignedData.getSignerInfos();
    Collection<SignerInformation> c = signers.getSigners();

    boolean result = false;

    for (SignerInformation signer : c)
    {
        SignerId signerId = signer.getSID();
        Collection certCollection = certs.getCertificates(signerId);

        Iterator certIt = certCollection.iterator();
        X509Certificate cert = (X509Certificate) certIt.next();
        result = signer.verify(cert, provider);

        if (result)
        {
            result = verifyAgainstCA(cert);
        }
        else
        {
            return false;
        }
    }

    return result;
  }

  public boolean verifyAgainstCA(X509Certificate cert) {
    // ********************* Verify signature ********************** //
    //get CA public key
    // Create a X509 certificat
    CertificateFactory certificatefactory = CertificateFactory.getInstance("X.509");

    // Open the certificate file
    FileInputStream fileinputstream = new FileInputStream(PATH_TO_CRT);

    //get CA public key
    PublicKey pk = certificatefactory.generateCertificate(fileinputstream).getPublicKey();

    X509Certificate myCA = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);

    return myCA.verify(pk);
  }

  public static void main(String[] args) throws Exception {

  }

}
