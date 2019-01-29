package codeprotection;

import static codeprotection.CodeProtection.parent;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CRLReason;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class CertificationAuthority {

    static public X509Certificate CASelfSignedCertificate;
    static KeyPair CAkeyPair;
    public static final String CAName = "C=CA,O=CA";
    public static final Provider bcProvider = new BouncyCastleProvider();

    static {
        if (!Files.exists(new File(CodeProtection.parent.toString() + File.separatorChar + "CA.cer").toPath(), LinkOption.NOFOLLOW_LINKS)) {
            try {
                Security.addProvider(bcProvider);
                
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(3072);
                CAkeyPair = keyGen.generateKeyPair();
                
                CASelfSignedCertificate = selfSign(CAkeyPair, CAName);
                CodeProtection.writeKey("CA", "password", CAkeyPair, parent);
            } 
            catch (IOException | NoSuchAlgorithmException | CertificateException | OperatorCreationException e) { e.printStackTrace();}
        } else {
            try {
                CASelfSignedCertificate = retrieveCertificate("CA");
                CAkeyPair = new KeyPair(CASelfSignedCertificate.getPublicKey(), CodeProtection.readKey("CA", "password", parent));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static X509Certificate selfSign(KeyPair keyPair, String name) throws OperatorCreationException, CertificateException, IOException 
    {
        Security.addProvider(bcProvider);

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 3); // 3 Year validity
        Date endDate = calendar.getTime();

        X500Name CAX500Name = new X500Name(name);
        BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // Using the current timestamp as the certificate serial number

        String signatureAlgorithm = "SHA256WithRSA";

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(CAX500Name, certSerialNumber, startDate, endDate, CAX500Name, keyPair.getPublic());

        BasicConstraints basicConstraints = new BasicConstraints(true); // true for CA, false for Subject

        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);

        return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
    }

    /*
    parameter name has to be in this format: "C=name,O=organization"
    */
    public X509Certificate createAndsignCertificate(String name, PublicKey publicKey) throws OperatorCreationException, CertIOException, CertificateException 
    {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1); // 1 Year validity
        Date endDate = calendar.getTime();

        BigInteger certSerialNumber = new BigInteger(Long.toString(now));

        X500Name CAX500Name = new X500Name(CAName);
        X500Name SubjectX500Name = new X500Name(name);

        String signatureAlgorithm = "SHA256WithRSA";
        
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(CAkeyPair.getPrivate());

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(CAX500Name, certSerialNumber, startDate, endDate, SubjectX500Name, publicKey);

        BasicConstraints basicConstraints = new BasicConstraints(false); // true for CA, false for Subject

        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);

        return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));

    }

    public static X509Certificate retrieveCertificate(String username) 
    {
        try (FileInputStream fileInput = new FileInputStream(parent.toString() + File.separatorChar + username + ".cer")) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate userCert = (X509Certificate) certificateFactory.generateCertificate(fileInput);
            return userCert;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public X509CRL generateCRLlist(X509Certificate ca, PrivateKey caPrivateKey, X509Certificate... revoked) throws Exception 
    {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(new X500Name(ca.getSubjectDN().getName()), new Date());

        for (X509Certificate certificate : revoked) {
            builder.addCRLEntry(certificate.getSerialNumber(), new Date(), CRLReason.PRIVILEGE_WITHDRAWN.ordinal());
        }

        if (Files.exists(new File(parent.getPath()+File.separatorChar+"CrlList.crl").toPath(), LinkOption.NOFOLLOW_LINKS)) 
        {
            try (FileInputStream in = new FileInputStream(new File(parent.getPath() + File.separatorChar + "CrlList.crl"))) 
            {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509CRL crl = (X509CRL) cf.generateCRL(in);
                Set s = crl.getRevokedCertificates();

                if (s != null && s.isEmpty() == false)
                {
                    Iterator t = s.iterator();
                    while (t.hasNext()) {
                        X509CRLEntry entry = (X509CRLEntry) t.next();
                        builder.addCRLEntry(entry.getSerialNumber(),entry.getRevocationDate(),CRLReason.UNSPECIFIED.ordinal());
                    }
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");

        contentSignerBuilder.setProvider(bcProvider);

        X509CRLHolder crlHolder = builder.build(contentSignerBuilder.build(caPrivateKey));

        JcaX509CRLConverter converter = new JcaX509CRLConverter();

        converter.setProvider(bcProvider);

        return converter.getCRL(crlHolder);
    }

    public void writeCRL(X509CRL crlList) 
    {
        try (PrintWriter printCRL = new PrintWriter(parent.getPath() + File.separatorChar + "CrlList.crl");
                JcaPEMWriter pemWriter = new JcaPEMWriter(printCRL)) {
            pemWriter.writeObject(crlList);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void IsValidCertificate(X509Certificate certificate)
    {
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException ex) {
            Alert alert = new Alert(Alert.AlertType.WARNING, "Certificate of message recipient is no longer valid" + " !", ButtonType.OK);
            alert.showAndWait();
        }
    }
}
