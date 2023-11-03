package com.da.crypto;

import com.da.crypto.service.CertificateService;
import com.sun.jarsigner.ContentSigner;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.FileWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Calendar;
import java.util.Date;

@SpringBootApplication
public class CryptoApplication implements  CommandLineRunner {

	CertificateService service = new CertificateService();

	public static void main(String[] args) {
		SpringApplication.run(CryptoApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		// Generate Key-Pair
		KeyPair keyPair =service.generateKeyPair();

		// Generate X509 certificate
		X509Certificate certificate = service.generateX509Certificate(keyPair);

		// Print Console and File PEM and Private KEY
		service.printCertificate(certificate, keyPair.getPrivate());
	}

}
