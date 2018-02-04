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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.CMSProcessable;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Enumeration;
import java.util.Collection;
import java.util.Iterator;
// --------------------------------

public class PCExample {

  private static final String PUBLIC_CERT = "public.crt";
  private static final String PRIVATE_CERT = "private.pfx";
  private static final String PWD_KEYSTORE = "2c2p";
  private static final String PWD_PUBLIC_CERT = "";

  public PCExample() {

  }

  @SuppressWarnings("unchecked")
  public static void main(String[] args) {
    String message = "hello world";
    byte[] b = message.getBytes();
    String enmsg = getEncryptedString(b);
    System.out.println(enmsg);
    System.out.println(getDecryptedString(enmsg.getBytes()));
  }

  @SuppressWarnings("unchecked")
  public static String getEncryptedString(byte[] message)
      {
        Security.addProvider(new BouncyCastleProvider());

          CMSEnvelopedData enveloped  = null;
          try{
              KeyStore keyStore = null;
              String alias = "my-fake-alias";
              InputStream inStream = new FileInputStream(PUBLIC_CERT);

             if(inStream != null)
              {
                  keyStore = KeyStore.getInstance("BKS", "BC");
                  CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
                  Certificate certificate = factory.generateCertificate(inStream);
                  keyStore.load(null);
                  keyStore.setCertificateEntry(alias, certificate);
                  inStream.close();

                  System.out.println("########## KeyStore Dump ##########");

                  for (Enumeration en = keyStore.aliases(); en.hasMoreElements();)
                  {
                      String alias2 = (String)en.nextElement();

                      if (keyStore.isCertificateEntry(alias2))
                      {
                          System.out.println("Certificate Entry: " + alias2 + ", Subject: " + (((X509Certificate)keyStore.getCertificate(alias2)).getSubjectDN()));
                      }
                      else if (keyStore.isKeyEntry(alias2))
                      {
                          System.out.println("Key Entry: " + alias2 + ", Subject: " + (((X509Certificate)keyStore.getCertificate(alias2)).getSubjectDN()));
                      }
                  }

                  System.out.println();
              }
              X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
              CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
              gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider("BC"));
              CMSTypedData data = new CMSProcessableByteArray(message);
              enveloped = gen.generate(data, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
                                              .setProvider("BC").build());
              // enveloped = gen.generate(data, CMSEnvelopedDataGenerator.AES128_CBC, "BC");
              return new String(Base64.encode(enveloped.getEncoded()), "UTF-8");

         } catch (Exception ex) {
              System.err.println(ex.getMessage());
          }
          return  "";
      }

      @SuppressWarnings("unchecked")
      public static String getDecryptedString(byte[] cipher){
           byte[] contents = null;
           try{
               // read PrivateKey
               InputStream inStream =  new FileInputStream(PRIVATE_CERT);
               KeyStore keyStore = KeyStore.getInstance("BKS");
               keyStore.load(inStream, PWD_KEYSTORE.toCharArray());
               String alias = keyStore.aliases().nextElement();
               PrivateKey key = (PrivateKey)keyStore.getKey(alias, PWD_KEYSTORE.toCharArray()); // demo - PWD_PUBLIC_CERT prod - PWD_KEYSTORE
               Security.addProvider(new BouncyCastleProvider());
               CMSEnvelopedData enveloped = new CMSEnvelopedData(cipher);
               Collection recip = enveloped.getRecipientInfos().getRecipients();
               KeyTransRecipientInformation rinfo = (KeyTransRecipientInformation) recip.iterator().next();
               contents = rinfo.getContent(new JceKeyTransEnvelopedRecipient(key).setProvider("BC"));
               return new String(contents);
           } catch (Exception ex) {
               System.err.println(ex.getMessage());
           }
           return "";
       }

}
