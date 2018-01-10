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

public class PKCS7Signer {

    private static final String PATH_TO_KEYSTORE = "pkcs7.keystore";
    private static final String KEY_ALIAS_IN_KEYSTORE = "pkcs7-key-alias";
    private static final String KEYSTORE_PASSWORD = "pkcs7-password";
    private static final String SIGNATUREALGO = "SHA1withRSA";

    public PKCS7Signer() {
    }

    public KeyStore loadKeyStore() throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        InputStream is = new FileInputStream(PATH_TO_KEYSTORE);
        keystore.load(is, KEYSTORE_PASSWORD.toCharArray());
        return keystore;
    }

    public CMSSignedDataGenerator setUpProvider(final KeyStore keystore) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        Certificate[] certchain = (Certificate[]) keystore.getCertificateChain(KEY_ALIAS_IN_KEYSTORE);

        final List<Certificate> certlist = new ArrayList<Certificate>();

        for (int i = 0, length = certchain == null ? 0 : certchain.length; i < length; i++) {
            certlist.add(certchain[i]);
        }

        Store certstore = new JcaCertStore(certlist);

        Certificate cert = keystore.getCertificate(KEY_ALIAS_IN_KEYSTORE);

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATUREALGO).setProvider("BC").
                build((PrivateKey) (keystore.getKey(KEY_ALIAS_IN_KEYSTORE, KEYSTORE_PASSWORD.toCharArray())));

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").
                build()).build(signer, (X509Certificate) cert));

        generator.addCertificates(certstore);

        return generator;

    }

    public byte[] signPkcs7(final byte[] content, final CMSSignedDataGenerator generator) throws Exception {

        CMSTypedData cmsdata = new CMSProcessableByteArray(content);
        CMSSignedData signeddata = generator.generate(cmsdata, true);
        return signeddata.getEncoded();
    }

    public byte[] unsignPkcs7(String envelopedData) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        CMSSignedData signeddata = new CMSSignedData(Base64.decode(envelopedData.getBytes()));
        Store store = signeddata.getCertificates();
        SignerInformationStore signers = signeddata.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();
        //the following array will contain the content of encoded signed data
        byte[] data = null;
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            Collection certCollection = store.getMatches(signer.getSID());
            Iterator certIt = certCollection.iterator();
            X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                System.out.println("verified");
                CMSProcessable sc = signeddata.getSignedContent();
                data = (byte[]) sc.getContent();
            }
        }
        return data;
    }

    public static void main(String[] args) throws Exception {
      PKCS7Signer signer = new PKCS7Signer();
      KeyStore keyStore = signer.loadKeyStore();
      CMSSignedDataGenerator signatureGenerator = signer.setUpProvider(keyStore);

      String content = "some bytes to be signed";
      byte[] signedBytes = signer.signPkcs7(content.getBytes("UTF-8"), signatureGenerator);
      String signedString = new String(Base64.encode(signedBytes));
      System.out.println("Signed Encoded Bytes: " + signedString);

      byte[] unsignedBytes = signer.unsignPkcs7(signedString);
      String unsignedString = new String(unsignedBytes);
      System.out.println("Decoded String: " + unsignedString);
    }

}
