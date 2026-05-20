package generiek.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import generiek.AbstractIntegrationTest;
import generiek.WireMockExtension;
import generiek.config.BackendConfiguration;
import generiek.model.Association;
import generiek.model.EnrollmentRequest;
import generiek.model.PersonAuthentication;
import io.restassured.http.ContentType;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.restassured.RestAssured.given;
import static java.util.Collections.singletonMap;
import static org.apache.http.HttpStatus.SC_MOVED_TEMPORARILY;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

public class EnrollmentEndpointTest extends AbstractIntegrationTest {

    private static RSAKey rsaKey;
    private static JWSSigner jwsSigner;
    private static Map<String, Object> jwkSetMap;
    private static final String keyId = UUID.randomUUID().toString();

    private static final BouncyCastleProvider bcProvider = new BouncyCastleProvider();

    static {
        Security.addProvider(bcProvider);
    }

    private final TypeReference<Map<String, Object>> mapRef = new TypeReference<Map<String, Object>>() {
    };

    @Autowired
    protected ObjectMapper objectMapper;

    @Autowired
    private BackendConfiguration backendConfiguration;

    @RegisterExtension
    WireMockExtension mockServer = new WireMockExtension(8081);

    @Value("${oidc.authorization-uri}")
    private String authorizationUri;

    @Value("${broker.url}")
    private String brokerUrl;

    @BeforeAll
    static void beforeAll() throws JOSEException, NoSuchAlgorithmException, NoSuchProviderException {
        EnrollmentEndpointTest.rsaKey = generateRsaKey(keyId);
        EnrollmentEndpointTest.jwkSetMap = new JWKSet(rsaKey.toPublicJWK()).toJSONObject();
        EnrollmentEndpointTest.jwsSigner = new RSASSASigner(rsaKey);
    }

    @Test
    void expiredEnrollmentRequest() {
        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("user", "secret")
                .header("X-Correlation-ID", "nope")
                .body(singletonMap("N/", "A"))
                .post("/api/start")
                .then()
                .body("status", equalTo(409));
    }

    @Test
    void expiredEnrollmentRequestInResults() {
        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(singletonMap("N/", "A"))
                .post("/associations/external/nope")
                .then()
                .body("status", equalTo(409));
    }

    @Test
    void fullScenario() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());
        doAssociate(correlationId);
    }

    @Test
    void fullScenarioWithPostPersonAuth() throws Exception {
        String state = doAuthorize(PersonAuthentication.FORM.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.FORM.name());
        doAssociate(correlationId);
    }

    @Test
    void fullScenarioWithBackendOauth() throws Exception {
        String originalAuthenticationType = backendConfiguration.getAuthenticationType();

        try {
            backendConfiguration.setAuthenticationType("oauth");
            backendConfiguration.setOidcAuthorizationUri(URI.create("http://localhost:8081/backend/oauth/token"));
            backendConfiguration.setOidcClientId("backend-client");
            backendConfiguration.setOidcClientSecret("backend-secret");
            backendConfiguration.setOidcScope("backend-scope");

            String state = doAuthorize(PersonAuthentication.HEADER.name());
            String correlationId = doToken(state);
            doStart(correlationId, PersonAuthentication.HEADER.name());

            verify(postRequestedFor(urlPathEqualTo("/backend/oauth/token")));
            verify(postRequestedFor(urlPathMatching("/intake"))
                    .withHeader("Authorization", containing("Bearer backend-access-token")));
        } finally {
            backendConfiguration.setAuthenticationType(originalAuthenticationType);
        }
    }

    @Test
    void associateEnrollmentRequest() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());
        Association association = doAssociate(correlationId);
        doPatchAssociate(association.getAssociationId());
    }

    @Test
    void fullScenarioWithPlay() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());
        doPlayReportBackResults(correlationId);
    }

    @Test
    void fullScenarioWithPlayVersion4() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("associationsURI", "http://localhost:8081/associations")))));

        //Because we are not sending an associationId, it will create one
        stubFor(post(urlPathMatching("/associations/me")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("res", "ok")))));

        Map<String, Object> results = objectMapper.readValue(readFile("data/results.json"), mapRef);
        results.put("v4", true);

        Map map = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .header("X-Correlation-ID", correlationId)
                .auth().basic("sis", "secret")
                .body(results)
                .post("/api/play-results")
                .as(Map.class);
        assertEquals("ok", map.get("res"));

    }

    @Test
    void invalidServiceRegistryEndpoint() throws JsonProcessingException {
        stubFor(post(urlPathMatching("/api/validate-service-registry-endpoints")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("valid", false)))));

        String location = given().redirects().follow(false)
                .when()
                .header("Content-Type", APPLICATION_FORM_URLENCODED_VALUE)
                .param("personURI", "http://localhost:8081/person")
                .param("personAuth", PersonAuthentication.HEADER.name())
                .param("homeInstitution", "schac.home")
                .param("scope", "write")
                .post("/api/enrollment")
                .header("Location");
        assertEquals("http://localhost:3003?error=412", location);
    }

    @Test
    void invalidTokenResult() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());

        String accessToken = accessToken(new HashMap<>());
        Map<String, String> tokenResult = new HashMap<>();
        tokenResult.put("access_token", accessToken);
        tokenResult.put("refresh_token", accessToken);
        tokenResult.put("id_token", accessToken);

        stubFor(post(urlPathMatching("/oidc/token")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(tokenResult))));

        String location = given().redirects().follow(false)
                .when()
                .queryParam("code", "123456")
                .queryParam("state", state)
                .get("/redirect_uri")
                .header("Location");
        assertEquals("http://localhost:3003?error=419", location);
    }

    @Test
    @SuppressWarnings("unchecked")
    void tokenNotValid() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("associationsURI", "http://localhost:8081/associations")))));
        stubFor(post(urlPathMatching("/oidc/token")).willReturn(aResponse()
                .withStatus(500)));
        //Ensure this goes wrong otherwise no new tokens are fetched
        stubFor(post(urlPathMatching("/associations/external/me")).willReturn(aResponse().withStatus(500)));

        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        Map<String, Object> res = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap())
                .pathParam("personId", enrollmentRequest.getEduid())
                .post("/associations/external/{personId}")
                .as(Map.class);

        assertTrue(((String) res.get("description")).startsWith("Error in obtaining new accessToken"));
        assertEquals(true, res.get("error"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void tokenRefresh() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("associationsURI", "http://localhost:8081/associations")))));

        Map<String, String> tokenResult = new HashMap<>();
        tokenResult.put("access_token", "123456");
        tokenResult.put("refresh_token", "123456");

        stubFor(post(urlPathMatching("/oidc/token")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(tokenResult))));
        //Ensure this goes wrong otherwise no new tokens are fetched
        stubFor(post(urlPathMatching("/associations/external/me")).willReturn(aResponse().withStatus(500)));

        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        Map<String, Object> res = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap())
                .pathParam("personId", enrollmentRequest.getEduid())
                .post("/associations/external/{personId}")
                .as(Map.class);

        assertEquals(true, res.get("error"));
    }

    @Test
    void associationUriInvalid() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());
        Association association = doAssociate(correlationId);

        stubFor(post(urlPathMatching("/api/associations-uri"))
                .willReturn(aResponse().withStatus(403)
                        .withHeader("Content-Type", "application/json")));

        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap<>())
                .pathParam("associationId", association.getAssociationId())
                .patch("/associations/{associationId}")
                .then()
                .statusCode(403);
    }

    @Test
    @SuppressWarnings("unchecked")
    void associationsUriNotValid() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());

        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withStatus(400)));

        Map<String, Object> res = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap<>())
                .pathParam("personId", enrollmentRequest.getEduid())
                .post("/associations/external/{personId}")
                .as(Map.class);

        assertTrue(((String) res.get("description")).startsWith("Error in obtaining associationURI"));
        assertEquals(true, res.get("error"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void ooApiResultsNotValid() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("associationsURI", "http://localhost:8081/associations")))));


        stubFor(post(urlPathMatching("/associations/external/me")).willReturn(aResponse()
                .withStatus(500)));

        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();
        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap<>())
                .pathParam("personId", enrollmentRequest.getEduid())
                .post("/associations/external/{personId}")
                .then()
                .statusCode(500);
    }

    @Test
    void resultsV4() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("associationsURI", "http://localhost:8081/associations")))));

        stubFor(post(urlPathMatching("/associations/me")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withStatus(200)
                .withBody("{}")));

        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(singletonMap("personId", enrollmentRequest.getEduid()))
                .post("/api/results")
                .then()
                .statusCode(200);
    }

    @Test
    void resultsV4ServiceRegistryException() throws NoSuchAlgorithmException, IOException, NoSuchProviderException, JOSEException {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withStatus(403)));

        Map map = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(singletonMap("personId", enrollmentRequest.getEduid()))
                .post("/api/results")
                .as(Map.class);
        assertTrue((Boolean) map.get("error"));
    }

    @Test
    void person() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        stubFor(post(urlPathMatching("/api/persons-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("personsURI", "http://localhost:8081/person/me")))));

        stubFor(get(urlPathMatching("/person/me")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withStatus(200)
                .withBody("{}")));

        Map results = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .pathParam("personId", enrollmentRequest.getEduid())
                .get("/person/{personId}")
                .as(Map.class);
        assertEquals(enrollmentRequest.getEduid(), results.get("personId"));
    }

    @Test
    void personInvalidURI() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        stubFor(post(urlPathMatching("/api/persons-uri")).willReturn(aResponse()
                .withStatus(404)));

        Map results = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .pathParam("personId", enrollmentRequest.getEduid())
                .get("/person/{personId}")
                .as(Map.class);
        assertTrue((Boolean) results.get("error"));
    }

    @Test
    void personInvalidAPiCall() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        stubFor(post(urlPathMatching("/api/persons-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("personsURI", "http://localhost:8081/person/me")))));

        stubFor(get(urlPathMatching("/person/me")).willReturn(aResponse()
                .withStatus(404)));

        Map results = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .pathParam("personId", enrollmentRequest.getEduid())
                .get("/person/{personId}")
                .as(Map.class);
        assertTrue((Boolean) results.get("error"));
        assertNull(results.get("personId"));
    }

    @Test
    void me() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        stubFor(post(urlPathMatching("/api/persons-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("personsURI", "http://localhost:8081/person/me")))));

        stubFor(get(urlPathMatching("/person/me")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withStatus(200)
                .withBody("{}")));

        Map results = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .header("X-Correlation-ID", correlationId)
                .get("/api/me")
                .as(Map.class);
        assertEquals(enrollmentRequest.getEduid(), results.get("personId"));
    }

    @Test
    void invalidEnrollmentRequest() throws Exception {
        doAuthorize(PersonAuthentication.HEADER.name());

        String accessToken = accessToken(singletonMap("eduid", "123456789"));
        Map<String, String> tokenResult = new HashMap<>();
        tokenResult.put("access_token", accessToken);
        tokenResult.put("refresh_token", accessToken);
        tokenResult.put("id_token", accessToken);

        stubFor(post(urlPathMatching("/oidc/token")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(tokenResult))));

        String location = given().redirects().follow(false)
                .when()
                .queryParam("code", "123456")
                .queryParam("state", "bogus")
                .get("/redirect_uri")
                .header("Location");
        assertEquals("http://localhost:3003?error=417", location);
    }

    @Test
    void tokenException() {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        stubFor(post(urlPathMatching("/oidc/token")).willReturn(aResponse()
                .withStatus(400)));

        String location = given().redirects().follow(false)
                .when()
                .queryParam("code", "123456")
                .queryParam("state", state)
                .get("/redirect_uri")
                .then()
                .statusCode(SC_MOVED_TEMPORARILY)
                .extract()
                .header("Location");
        assertEquals("http://localhost:3003?error=417", location);
    }

    @Test
    void personEndpointException() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        String offering = readFile("data/offering.json");
        stubFor(get(urlPathMatching("/person")).willReturn(aResponse()
                .withStatus(500)));

        Map result = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("user", "secret")
                .header("X-Correlation-ID", correlationId)
                .body(offering)
                .post("/api/start")
                .as(Map.class);
        assertTrue(((String) result.get("description")).startsWith("Error in retrieving person for enrollmentRequest"));
        assertEquals(true, result.get("error"));
    }

    @Test
    void accessTokenNotStoredInDatabaseAndNotRefetchedOnSubsequentCalls() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state); // calls /oidc/token once

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("associationsURI", "http://localhost:8081/associations")))));
        stubFor(post(urlPathMatching("/associations/external/me")).willReturn(aResponse()
                .withStatus(201)
                .withBody(readFile("data/association_me.json"))
                .withHeader("Content-Type", "application/json")));

        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        // First call
        given().when()
                .contentType(ContentType.JSON).accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap<>())
                .pathParam("personId", enrollmentRequest.getEduid())
                .post("/associations/external/{personId}")
                .then().statusCode(201);

        // Second call — token must be reused, no extra fetch
        given().when()
                .contentType(ContentType.JSON).accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap<>())
                .pathParam("personId", enrollmentRequest.getEduid())
                .post("/associations/external/{personId}")
                .then().statusCode(201);

        // Token endpoint must have been called exactly once (during doToken, not during the two API calls)
        verify(exactly(1), postRequestedFor(urlPathMatching("/oidc/token")));
    }

    @Test
    void registrationBrokerException() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        String offering = readFile("data/offering.json");

        stubFor(get(urlPathMatching("/person")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(readFile("data/person.json"))));

        stubFor(post(urlPathMatching("/intake")).willReturn(aResponse()
                .withStatus(500)));

        Map result = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("user", "secret")
                .header("X-Correlation-ID", correlationId)
                .body(offering)
                .post("/api/start")
                .as(Map.class);
        assertTrue(((String) result.get("description")).startsWith("Error in registration results"));
        assertEquals(true, result.get("error"));
    }

    @SneakyThrows
    protected String doAuthorize(String personAuth) {
        stubFor(post(urlPathMatching("/api/validate-service-registry-endpoints")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("valid", true)))));

        String location = given().redirects().follow(false)
                .when()
                .header("Content-Type", APPLICATION_FORM_URLENCODED_VALUE)
                .param("personURI", "http://localhost:8081/person")
                .param("personAuth", personAuth)
                .param("homeInstitution", "schac.home")
                .param("scope", "write")
                .post("/api/enrollment")
                .header("Location");
        assertTrue(location.startsWith(authorizationUri));

        MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(location).build().getQueryParams();
        String scope = params.getFirst("scope");
        assertEquals("openid write", URLDecoder.decode(scope, "UTF-8"));
        return params.getFirst("state");
    }


    private String doToken(String state) throws JOSEException, IOException {
        Map<String, String> claims = new HashMap<>();
        claims.put("family_name", "Doe");
        claims.put("given_name", "John");
        claims.put("eduid", "1234567890");

        String accessToken = accessToken(claims);
        Map<String, String> tokenResult = new HashMap<>();
        tokenResult.put("access_token", accessToken);
        tokenResult.put("refresh_token", accessToken);
        tokenResult.put("id_token", accessToken);

        stubFor(post(urlPathMatching("/oidc/token")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(tokenResult))));

        String location = given()
                .redirects().follow(false)
                .when()
                .queryParam("code", "123456")
                .queryParam("state", state)
                .get("/redirect_uri")
                .then()
                .statusCode(SC_MOVED_TEMPORARILY)
                .extract()
                .header("Location");
        MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(location).build().getQueryParams();

        assertTrue(location.startsWith(brokerUrl));
        String correlationID = params.getFirst("correlationID");
        assertNotNull(correlationID);
        assertEquals("John", params.getFirst("name"));
        assertEquals("enroll", params.getFirst("step"));
        return correlationID;
    }

    private void doStart(String state, String personAuth) throws IOException {
        String offering = readFile("data/offering.json");
        if (personAuth.equalsIgnoreCase(PersonAuthentication.HEADER.name())) {
            stubFor(get(urlPathMatching("/person")).willReturn(aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(readFile("data/person.json"))));
        } else {
            stubFor(post(urlPathMatching("/person")).willReturn(aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(readFile("data/person.json"))));
        }

        stubFor(post(urlPathEqualTo("/backend/oauth/token"))
                .withRequestBody(containing("grant_type=client_credentials"))
                .withRequestBody(containing("client_id=backend-client"))
                .withRequestBody(containing("client_secret=backend-secret"))
                .withRequestBody(containing("scope=backend-scope"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(objectMapper.writeValueAsString(singletonMap("access_token", "backend-access-token")))));

        stubFor(post(urlPathMatching("/intake")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("result", "ok")))));

        Map result = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("user", "secret")
                .header("X-Correlation-ID", state)
                .body(offering)
                .post("/api/start")
                .as(Map.class);
        assertEquals("ok", result.get("result"));
    }

    private Association doAssociate(String correlationId) throws IOException {
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("associationsURI", "http://localhost:8081/associations")))));

        String content = readFile("data/association_me.json");

        stubFor(post(urlPathMatching("/associations/external/me")).willReturn(aResponse()
                .withStatus(201)
                .withBody(content)
                .withHeader("Content-Type", "application/json")
        ));

        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap<>())
                .pathParam("personId", enrollmentRequest.getEduid())
                .post("/associations/external/{personId}")
                .then()
                .statusCode(201);

        Association association = associationRepository.findByAssociationId("1234567890").get();
        assertEquals(correlationId, association.getEnrollmentRequest().getIdentifier());
        return association;
    }

    private void doPatchAssociate(String associationId) throws IOException {
        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("associationsURI", "http://localhost:8081/associations")))));

        String content = readFile("data/association_me.json");

        stubFor(patch(urlPathMatching("/associations/" + associationId)).willReturn(aResponse()
                .withBody(content)
                .withHeader("Content-Type", "application/json")
                .withStatus(200)));

        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap<>())
                .pathParam("associationId", associationId)
                .patch("/associations/{associationId}")
                .then()
                .statusCode(200);
        //Alternative GET
        stubFor(get(urlPathMatching("/associations/" + associationId)).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withStatus(200)));

        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .pathParam("associationId", associationId)
                .get("/associations/{associationId}")
                .then()
                .statusCode(200);
    }

    private void doPlayReportBackResults(String correlationId) throws IOException {
        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(singletonMap("associationsURI", "http://localhost:8081/associations")))));

        //Because we are not sending an associationId, it will create one
        String associationId = UUID.randomUUID().toString();
        String bodyFromHomeInstitution = objectMapper.writeValueAsString(singletonMap("associationId", associationId));
        stubFor(post(urlPathMatching("/associations/external/me")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withStatus(201)
                .withBody(bodyFromHomeInstitution)));

        Map<String, Object> results = objectMapper.readValue(readFile("data/results.json"), mapRef);

        Map map = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .header("X-Correlation-ID", correlationId)
                .auth().basic("sis", "secret")
                .body(results)
                .post("/api/play-results")
                .as(Map.class);
        assertEquals(associationId, map.get("associationId"));

        stubFor(patch(urlPathMatching("/associations/(.*)")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(bodyFromHomeInstitution)));

        //The return map contains the associationId, and therefore it will update the association
        results.putAll(map);

        map = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .header("X-Correlation-ID", correlationId)
                .auth().basic("sis", "secret")
                .body(results)
                .post("/api/play-results")
                .as(Map.class);

        assertEquals(associationId, map.get("associationId"));
    }

    private String readFile(String path) throws IOException {
        return IOUtils.toString(new ClassPathResource(path).getInputStream());
    }

    protected String accessToken(Map<String, String> claims) throws JOSEException, IOException {
        stubFor(get(urlPathMatching("/oidc/certs")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(jwkSetMap))));

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .audience("audiences")
                .expirationTime(Date.from(Instant.now().plus(60 * 60, ChronoUnit.SECONDS)))
                .jwtID(UUID.randomUUID().toString())
                .issuer("issuer")
                .claim("scope", Arrays.asList("openid", "profile"))
                .issueTime(Date.from(Instant.now()))
                .subject("subject")
                .notBeforeTime(new Date(System.currentTimeMillis()));
        claims.forEach(builder::claim);
        JWTClaimsSet claimsSet = builder.build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT)
                .keyID(keyId).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(jwsSigner);
        return signedJWT.serialize();
    }

    private static RSAKey generateRsaKey(String keyID) throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(keyID)
                .build();
    }
}