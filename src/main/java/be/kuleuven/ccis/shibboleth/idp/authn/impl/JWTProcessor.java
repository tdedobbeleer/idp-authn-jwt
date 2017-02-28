package be.kuleuven.ccis.shibboleth.idp.authn.impl;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Map;
import java.util.stream.Collectors;

import static java.time.temporal.ChronoUnit.MINUTES;

/**
 * Created by philip on 28.02.17.
 */
public class JWTProcessor {

    /**
     * Class logger.
     */
    @Nonnull
    @NotEmpty
    private final Logger log = LoggerFactory.getLogger(JWTProcessor.class);

    private ECPrivateKey privateKey;
    private ECPublicKey publicKey;
    private ArrayList<JWEAlgorithm> jweAlgorithms;
    private ArrayList<JWSAlgorithm> jwsAlgorithms;
    private ArrayList<EncryptionMethod> encryptionMethods;
    private Duration expiration;
    private Map<String, ECPublicKey> issuers;

    public JWTProcessor(String privatekey,
                        ArrayList jweAlgorithms,
                        ArrayList jwsAlgorithms,
                        ArrayList jweEncMethods,
                        String jwtExpiration,
                        Map<String,String> trustedIssuers) {

        KeyPair keyPair = this.getKeyPair(privatekey);
        // Set private + public EC key
        this.privateKey = (ECPrivateKey)keyPair.getPrivate();
        this.publicKey = (ECPublicKey)keyPair.getPublic();

        this.jweAlgorithms = jweAlgorithms;
        this.jwsAlgorithms = jwsAlgorithms;
        this.encryptionMethods = jweEncMethods;
        this.expiration = Duration.parse(jwtExpiration);

        this.issuers = trustedIssuers.entrySet().stream()
                        .collect(Collectors.toMap(
                                e -> e.getKey(),
                                e -> (ECPublicKey) this.getKeyPair(e.getValue()).getPublic()
                        ));
    }

    private KeyPair getKeyPair(String keypair){
        KeyPair keyPair = null;
        // Load BouncyCastle as JCA provider
        Security.addProvider(new BouncyCastleProvider());
        try {
            // Parse the EC key pair
            PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream(keypair)));
            PEMKeyPair pemKeyPair = (PEMKeyPair)pemParser.readObject();
            // Convert to Java (JCA) format
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            keyPair = converter.getKeyPair(pemKeyPair);
            pemParser.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

    public String validateAndExtractSubjectFromJWT(String jwt) {

        String subject = null;
        try {
            JWEObject jweObject = JWEObject.parse(jwt);
            if (! jweAlgorithms.contains(jweObject.getHeader().getAlgorithm()) ||
                  ! encryptionMethods.contains(jweObject.getHeader().getEncryptionMethod())) {
                log.error("JWE was encrypted using a different algorithm ({}) or encryption method ({})",
                        jweObject.getHeader().getAlgorithm(),
                        jweObject.getHeader().getEncryptionMethod());
                return null;
            }

            jweObject.decrypt(new ECDHDecrypter(this.privateKey));

            SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
            if(! jwsAlgorithms.contains(signedJWT.getHeader().getAlgorithm())) {
                log.error("JWS was signed using a different algorithm ({})", signedJWT.getHeader().getAlgorithm());
                return null;
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            if(! issuers.containsKey(claimsSet.getIssuer())) {
                log.error("JWS did not came from a trusted issuer: {}", claimsSet.getIssuer());
                return null;
            }

            if(signedJWT.verify(new ECDSAVerifier(issuers.get(claimsSet.getIssuer())))) {
                log.info("Signature of JWT signed by {} is correct", claimsSet.getIssuer());
                LocalDateTime issueTime = claimsSet.getIssueTime().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();

                if (issueTime.plus(expiration).isAfter(LocalDateTime.now())){
                    log.info("JWT is still valid. JWT was created at: ", issueTime.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
                    subject = claimsSet.getSubject();
                } else {
                    log.error("JWT has expired. Issued at {}. Expiration at {}.",
                            issueTime.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
                            issueTime.plus(expiration).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
                    return null;
                }

            }

        } catch (ParseException e) {
            log.error("Unable to parse JWT: {}", e.getMessage());
        } catch (JOSEException e) {
            log.error("Unable to decrypt or verify signature: {}", e.getMessage());
        }
        return subject;

    }
}
