package be.kuleuven.ccis.shibboleth.idp.authn.impl;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


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
    private List<JWEAlgorithm> jweAlgorithms;
    private List<JWSAlgorithm> jwsAlgorithms;
    private List<EncryptionMethod> encryptionMethods;
    private Duration expiration;
    private Map<String, ECPublicKey> issuers;

    public JWTProcessor(String privatekey,
                        List<String> jweAlgorithms,
                        List<String> jwsAlgorithms,
                        List<String> jweEncMethods,
                        String jwtExpiration,
                        Map<String,String> trustedIssuers) {

        // Load BouncyCastle as JCA provider
        Security.addProvider(new BouncyCastleProvider());

        KeyPair keyPair = this.getKeyPair(privatekey);
        // Set private + public EC key
        this.privateKey = (ECPrivateKey)keyPair.getPrivate();
        this.publicKey = (ECPublicKey)keyPair.getPublic();

        this.jweAlgorithms = jweAlgorithms.stream().map(e -> JWEAlgorithm.parse(e)).collect(Collectors.toList());
        this.jwsAlgorithms = jwsAlgorithms.stream().map(e -> JWSAlgorithm.parse(e)).collect(Collectors.toList());
        this.encryptionMethods = jweEncMethods.stream().map(e -> EncryptionMethod.parse(e)).collect(Collectors.toList());
        this.expiration = Duration.parse(jwtExpiration);

        this.issuers = trustedIssuers.entrySet().stream()
                        .collect(Collectors.toMap(
                                e -> e.getKey(),
                                e -> (ECPublicKey) this.getPublicKey(e.getValue())
                        ));
    }


    private PublicKey getPublicKey(String file){

        try {
            // Parse the EC key pair
            PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream(file)));
            SubjectPublicKeyInfo pemKeyPair = (SubjectPublicKeyInfo) pemParser.readObject();
            pemParser.close();
            // Convert to Java (JCA) format
            return new JcaPEMKeyConverter().getPublicKey(pemKeyPair);
        } catch (IOException e) {
            log.error("Failed to parse public key: {}", file);
        }
        return null;
    }

    private KeyPair getKeyPair(String file){


        try {
            // Parse the EC key pair
            PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream(file)));
            PEMKeyPair pemKeyPair = (PEMKeyPair)pemParser.readObject();
            // Convert to Java (JCA) format
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            pemParser.close();
            return converter.getKeyPair(pemKeyPair);
        } catch (IOException e) {
            log.error("Failed to parse keypair key: {}", file);
        }
        return null;
    }

    public String validateAndExtractSubjectFromJWT(String jwt) {

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

            if(claimsSet.getIssueTime() == null) {
                log.error("Claimset did not have a iat (issuetime): {}", claimsSet.toJSONObject().toJSONString());
                return null;
            }

            if(signedJWT.verify(new ECDSAVerifier(issuers.get(claimsSet.getIssuer())))) {
                log.info("Signature of JWT signed by {} is correct", claimsSet.getIssuer());
                ZonedDateTime issueTime = ZonedDateTime.ofInstant(claimsSet.getIssueTime().toInstant(), ZoneId.systemDefault());

                if (issueTime.plus(expiration).isAfter(ZonedDateTime.now())){
                    log.info("JWT is still valid. JWT was created at: ", issueTime.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
                    return claimsSet.getSubject();
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
        return null;

    }
}
