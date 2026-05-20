package generiek.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import generiek.LanguageFilter;
import generiek.ServiceRegistry;
import generiek.config.BackendConfiguration;
import generiek.exception.ExpiredEnrollmentRequestException;
import generiek.jwt.JWTValidator;
import generiek.model.Association;
import generiek.model.EnrollmentRequest;
import generiek.model.PersonAuthentication;
import generiek.ooapi.EnrollmentAssociation;
import generiek.repository.AssociationRepository;
import generiek.repository.EnrollmentRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.SneakyThrows;
import okhttp3.ConnectionPool;
import okhttp3.OkHttpClient;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.oer.its.etsi102941.EnrolmentRequestMessage;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.OkHttp3ClientHttpRequestFactory;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URLEncoder;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;


@RestController
@Tag(name = "Enrollment", description = "Endpoints for managing the student enrollment lifecycle")
public class EnrollmentEndpoint {

    private static final Log LOG = LogFactory.getLog(EnrollmentEndpoint.class);

    private final String acr;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final URI authorizationUri;
    private final URI tokenUri;
    private final BackendConfiguration backendConfiguration;
    private final String brokerUrl;
    private final ServiceRegistry serviceRegistry;
    private final boolean allowPlayground;
    private final boolean eduIDRequired;
    private final EnrollmentRepository enrollmentRepository;
    private final AssociationRepository associationRepository;
    private final ObjectMapper objectMapper;

    private final RestTemplate restTemplate;
    private final ParameterizedTypeReference<Map<String, Object>> mapRef = new ParameterizedTypeReference<Map<String, Object>>() {
    };
    private final JWTValidator jwtValidator;

    private final Cache<String, String> accessTokenCache = Caffeine.newBuilder()
            .expireAfter(new Expiry<String, String>() {
                @Override
                public long expireAfterCreate(String key, String token, long currentTime) {
                    try {
                        JWTClaimsSet claims = JWTParser.parse(token).getJWTClaimsSet();
                        long expSeconds = claims.getExpirationTime().toInstant().getEpochSecond();
                        long nowSeconds = Instant.now().getEpochSecond();
                        long secondsUntilExpiry =  Math.max(expSeconds - nowSeconds, 0);
                        long cappedSeconds = Math.min(secondsUntilExpiry, 600); // max 10 min
                        return TimeUnit.SECONDS.toNanos(cappedSeconds);
                    } catch (Exception e) {
                        return 0;
                    }
                }

                @Override
                public long expireAfterUpdate(String key, String token, long currentTime, long currentDuration) {
                    return expireAfterCreate(key, token, currentTime);
                }

                @Override
                public long expireAfterRead(String key, String token, long currentTime, long currentDuration) {
                    return currentDuration;
                }
            })
            .build();

    public EnrollmentEndpoint(@Value("${oidc.acr-context-class-ref}") String acr,
                              @Value("${oidc.client-id}") String clientId,
                              @Value("${oidc.client-secret}") String clientSecret,
                              @Value("${oidc.redirect-uri}") String redirectUri,
                              @Value("${oidc.authorization-uri}") URI authorizationUri,
                              @Value("${oidc.token-uri}") URI tokenUri,
                              @Value("${oidc.jwk-set-uri}") String jwkSetUri,
                              BackendConfiguration backendConfiguration,
                              @Value("${broker.url}") String brokerUrl,
                              @Value("${features.allow_playground}") boolean allowPlayground,
                              @Value("${features.require_eduid}") boolean eduIDRequired,
                              @Value("${config.connection_timeout_millis}") int connectionTimeoutMillis,
                              @Value("${config.connection_pool_keep_alive_duration_millis}") int keepAliveDurationMillis,
                              @Value("${config.connection_pool_max_idle_connections}") int maxIdleConnections,
                              @Value("${oidc.jwk.connect-timeout}") int jwkConnectionTimeout,
                              @Value("${oidc.jwk.read-timeout}") int jwkReadTimeout,
                              @Value("${oidc.jwk.size-limit}") int jwkSizeLimit,
                              EnrollmentRepository enrollmentRepository,
                              AssociationRepository associationRepository,
                              ServiceRegistry serviceRegistry,
                              ObjectMapper objectMapper) throws MalformedURLException {
        this.acr = acr;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.authorizationUri = authorizationUri;
        this.tokenUri = tokenUri;
        this.jwtValidator = new JWTValidator(jwkSetUri, jwkConnectionTimeout, jwkReadTimeout, jwkSizeLimit);
        this.backendConfiguration = backendConfiguration;
        this.brokerUrl = brokerUrl;
        this.enrollmentRepository = enrollmentRepository;
        this.associationRepository = associationRepository;
        this.serviceRegistry = serviceRegistry;
        this.objectMapper = objectMapper;
        this.allowPlayground = allowPlayground;
        this.eduIDRequired = eduIDRequired;
        // Otherwise, we can't use method PATCH
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder
                .connectTimeout(connectionTimeoutMillis, TimeUnit.MILLISECONDS)
                .readTimeout(connectionTimeoutMillis, TimeUnit.MILLISECONDS)
                .retryOnConnectionFailure(true)
                .connectionPool(new ConnectionPool(maxIdleConnections, keepAliveDurationMillis, TimeUnit.MILLISECONDS));

        ClientHttpRequestFactory requestFactory = new OkHttp3ClientHttpRequestFactory(builder.build());
        if (LOG.isDebugEnabled()) {
            //This allows us to read the response body twice, which has a performance overhead
            requestFactory = new BufferingClientHttpRequestFactory(requestFactory);
        }
        this.restTemplate = new RestTemplate(requestFactory);
        this.restTemplate.getInterceptors().add((request, body, execution) -> {
            request.getHeaders().add("Accept-Language", LanguageFilter.language.get());
            //Bugfix for too strict DefaultBearerTokenResolver which does not ignore CHARSET
            List<String> contentType = request.getHeaders().get("Content-Type");
            if (!CollectionUtils.isEmpty(contentType) && contentType.getFirst().startsWith("application/x-www-form-urlencoded")) {
                request.getHeaders().set("Content-Type", "application/x-www-form-urlencoded");
            }
            return execution.execute(request, body);
        });
        this.restTemplate.getInterceptors().add(new RestTemplateLoggingInterceptor());
    }

    @InitBinder
    public void initBinder(WebDataBinder dataBinder) {
        String[] denylist = new String[]{"class.*", "Class.*", "*.class.*", "*.Class.*"};
        dataBinder.setDisallowedFields(denylist);
    }

    /*
     * Endpoint called by the student-mobility-broker form submit
     */
    @Operation(summary = "Initiate Enrollment",
            description = "Receives the enrollment request from the broker and redirects the student to the OIDC provider.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirect to authorization URI"),
            @ApiResponse(responseCode = "412", description = "Invalid enrollment request (validation failed)")
    })
    @PostMapping(value = "/api/enrollment", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public View enrollment(@ModelAttribute EnrollmentRequest enrollmentRequest) throws IOException {
        LOG.debug("Received authorization for enrollment request: " + enrollmentRequest);
        // Prevent forgery and cherry-pick attributes
        try {
            enrollmentRequest = new EnrollmentRequest(enrollmentRequest);
            // Check the broker-serviceregistry to validate the personURI and homeInstitution before continuing
            this.validateServiceRegistryEndpoints(enrollmentRequest);
        } catch (RuntimeException e) {
            LOG.error("Invalid enrollmentRequest: " + enrollmentRequest, e);
            if (e instanceof HttpClientErrorException) {
                HttpClientErrorException ex = (HttpClientErrorException) e;
                LOG.error("Invalid enrollmentRequest: " + ex.getResponseBodyAsString());
            }
            String redirect = String.format("%s?error=%s", brokerUrl, 412);
            return new RedirectView(redirect, false);
        }
        //Start authorization flow
        String authorizationURI = this.buildAuthorizationURI(enrollmentRequest);

        LOG.debug("Starting authorization for enrollment request: " + enrollmentRequest);

        return new RedirectView(authorizationURI);
    }

    /*
     * Redirect after authentication. Give browser-control back to the client to call start and show progress-spinner
     */
    @Operation(summary = "Redirect after authentication",
            description = "Give browser-control back to the client to call start and show progress-spinne.")
    @GetMapping("/redirect_uri")
    public View redirect(@RequestParam("code") String code, @RequestParam("state") String state) throws ParseException, IOException, BadJOSEException, JOSEException {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        map.add("client_secret", clientSecret);
        map.add("code", code);
        map.add("grant_type", "authorization_code");
        map.add("redirect_uri", redirectUri);

        Map<String, Object> body;
        try {
            body = tokenRequest(map);
        } catch (RestClientException e) {
            LOG.error("Exception in token request", e);

            String redirect = String.format("%s?error=%s", brokerUrl, 417);
            return new RedirectView(redirect, false);
        }

        String accessToken = (String) body.get("access_token");
        String refreshToken = (String) body.get("refresh_token");
        String idToken = (String) body.get("id_token");

        jwtValidator.validate(accessToken);
        JWTClaimsSet claimsSet = jwtValidator.validate(idToken);

        String givenName = claimsSet.getStringClaim("given_name");
        //Very unlikely and why break on this?
        givenName = StringUtils.hasText(givenName) ? givenName : "Mystery guest";
        givenName = URLEncoder.encode(givenName, "UTF-8");

        String eduid = claimsSet.getStringClaim("eduid");
        if (!StringUtils.hasText(eduid) && this.eduIDRequired) {
            LOG.error("eduid is required. Check the ARP for RP:" + this.clientId);
            String redirect = String.format("%s?error=%s", brokerUrl, 419);
            return new RedirectView(redirect, false);
        }
        EnrollmentRequest enrollmentRequest;
        try {
            enrollmentRequest = EnrollmentRequest.serializeFromBase64(objectMapper, state);
        } catch (IllegalArgumentException | IOException e) {
            LOG.error("Redirect after authorization called and no valid enrollment request", e);

            String redirect = String.format("%s?error=%s", brokerUrl, 417);
            return new RedirectView(redirect, false);
        }

        LOG.debug("Redirect after authorization called for enrollment request: " + enrollmentRequest);
        if (this.eduIDRequired) {
            enrollmentRequest.setEduid(eduid);
        }
        accessTokenCache.put(enrollmentRequest.getIdentifier(), accessToken);
        enrollmentRequest.setRefreshToken(refreshToken);
        enrollmentRepository.save(enrollmentRequest);

        String redirect = String.format("%s?step=enroll&correlationID=%s&name=%s",
                brokerUrl, enrollmentRequest.getIdentifier(), givenName);

        LOG.debug(String.format("Redirecting back to %s client after authorization", redirect));

        return new RedirectView(redirect, false);
    }

    private Map<String, Object> tokenRequest(MultiValueMap<String, String> map) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        return restTemplate.exchange(tokenUri, HttpMethod.POST, request, mapRef).getBody();
    }

    private HttpEntity<Map<String, Object>> createBackendHttpEntity(Map<String, Map<String, Object>> body) {
        HttpHeaders httpHeaders = new HttpHeaders();
        if ("oauth".equalsIgnoreCase(backendConfiguration.getAuthenticationType())) {
            httpHeaders.setBearerAuth(fetchBackendAccessToken());
        } else {
            httpHeaders.setBasicAuth(backendConfiguration.getApiUser(), backendConfiguration.getApiPassword());
        }
        return new HttpEntity(body, httpHeaders);
    }

    private String fetchBackendAccessToken() {
        if (backendConfiguration.getOidcAuthorizationUri() == null
                || !StringUtils.hasText(backendConfiguration.getOidcClientId())
                || !StringUtils.hasText(backendConfiguration.getOidcClientSecret())) {
            throw new IllegalStateException("backend oauth configuration is incomplete");
        }

        MultiValueMap<String, String> tokenRequestBody = new LinkedMultiValueMap<>();
        tokenRequestBody.add("grant_type", "client_credentials");
        tokenRequestBody.add("client_id", backendConfiguration.getOidcClientId());
        tokenRequestBody.add("client_secret", backendConfiguration.getOidcClientSecret());
        if (StringUtils.hasText(backendConfiguration.getOidcScope())) {
            tokenRequestBody.add("scope", backendConfiguration.getOidcScope());
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        HttpEntity<MultiValueMap<String, String>> tokenRequestEntity = new HttpEntity<>(tokenRequestBody, headers);

        Map<String, Object> tokenResponse = restTemplate.exchange(backendConfiguration.getOidcAuthorizationUri(), HttpMethod.POST, tokenRequestEntity, mapRef).getBody();
        String accessToken = tokenResponse == null ? null : (String) tokenResponse.get("access_token");
        if (!StringUtils.hasText(accessToken)) {
            throw new IllegalStateException("backend oauth token endpoint did not return an access_token");
        }
        return accessToken;
    }

    /*
     * Start the actual enrollment based on the data returned from the 'me' endpoint
     */
    @Operation(summary = "Start Registration",
            description = "Triggers the actual registration at the guest institution using the student's data.")
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
        description = "The OOAPI v4 Offering object representing the course or component the student is enrolling in.",
        required = true,
        content = @Content(
            mediaType = MediaType.APPLICATION_JSON_VALUE,
            examples = @ExampleObject(
                name = "OOAPI v4 Offering Example",
                summary = "A comprehensive OOAPI v4 Offering example",
                value = "{\n" +
                        "  \"offeringId\": \"123e4567-e89b-12d3-a456-134564174000\",\n" +
                        "  \"offeringType\": \"component\",\n" +
                        "  \"academicSession\": \"937983ad-cc0f-45a6-95ca-a8f60b7cf125\",\n" +
                        "  \"name\": [{ \"language\": \"en-GB\", \"value\": \"Final written test for INFOMQNM\" }],\n" +
                        "  \"abbreviation\": \"Test-INFOMQNM-20FS\",\n" +
                        "  \"description\": [{ \"language\": \"en-GB\", \"value\": \"Research methods and statistics...\" }],\n" +
                        "  \"teachingLanguage\": \"nld\",\n" +
                        "  \"modeOfDelivery\": [ \"situated\" ],\n" +
                        "  \"startDate\": \"2019-08-21\",\n" +
                        "  \"endDate\": \"2023-06-15\",\n" +
                        "  \"enrollStartDate\": \"2019-05-01\",\n" +
                        "  \"enrollEndDate\": \"2019-08-01\",\n" +
                        "  \"resultExpected\": true,\n" +
                        "  \"resultValueType\": \"1-10\",\n" +
                        "  \"organization\": \"452c1a86-a0af-475b-b03f-724878b0f387\"\n" +
                        "}"
            )
        )
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200", 
            description = "Enrollment status (Success or Handled Error)",
            content = @Content(
                mediaType = MediaType.APPLICATION_JSON_VALUE,
                examples = {
                    @ExampleObject(
                        name = "Success Response",
                        summary = "Enrollment successfully initiated",
                        value = "{\n" +
                                "  \"result\": \"ok\",\n" +
                                "  \"code\": 200,\n" +
                                "  \"message\": \"Your enrollment request has been received.\",\n" +
                                "  \"oo-api-offering-id\": \"123e4567-e89b-12d3-a456-134564174000\",\n" +
                                "  \"redirect\": \"https://optional.redirect/for-extra-information\"\n" +
                                "}"
                    ),
                    @ExampleObject(
                        name = "Handled Backend Error",
                        summary = "Business error from SIS with support reference",
                        value = "{\n" +
                                "  \"result\": \"error\",\n" +
                                "  \"code\": 400,\n" +
                                "  \"message\": \"Student already registered for this component.\",\n" +
                                "  \"reference\": \"REQ-af82-238d-1192\",\n" +
                                "  \"oo-api-offering-id\": \"123e4567-e89b-12d3-a456-134564174000\"\n" +
                                "}"
                    )
                }
            )
        ),
        @ApiResponse(
            responseCode = "500", 
            description = "Technical connection failure",
            content = @Content(
                mediaType = MediaType.APPLICATION_JSON_VALUE,
                examples = @ExampleObject(
                    name = "Connection Exception",
                    summary = "Exception when communicating with the backend SIS",
                    value = "{\n" +
                            "  \"message\": \"Error in registration results for enrollmentRequest: ...\",\n" +
                            "  \"error\": \"Internal Server Error\"\n" +
                            "}"
                )
            )
        )
    })
    @PostMapping("/api/start")
    public ResponseEntity<Map<String, Object>> start(
            @RequestHeader("X-Correlation-ID") String correlationId,
            @RequestBody Map<String, Object> offering) {
        LOG.debug(String.format("Received start registration from broker for correlation-id %s and offering %s", correlationId, offering));

        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId)
                .orElseThrow(ExpiredEnrollmentRequestException::new);
        LOG.debug(String.format("Found matching enrollment request %s for correlation-id %s", enrollmentRequest, correlationId));

        Map<String, Map<String, Object>> body = new HashMap<>();
        body.put("offering", offering);
        Map<String, Object> personMap;
        try {
            personMap = person(enrollmentRequest);
        } catch (HttpStatusCodeException e) {
            return this.errorResponseEntity("Error in retrieving person for enrollmentRequest: " + enrollmentRequest, e);
        }
        if (this.eduIDRequired) {
            LOG.debug(String.format("Replacing personId %s with eduID %s", personMap.get("personId"), enrollmentRequest.getEduid()));
            personMap.put("personId", enrollmentRequest.getEduid());
        } else {
            String personId = (String) personMap.get("personId");
            LOG.debug(String.format("Updating enrollmentRequest with personId %s as eduIDRequired is false", personId));
            //TODO quick-fix, proper solution is to make the decision explicit
            enrollmentRequest.setEduid(personId);
            this.enrollmentRepository.save(enrollmentRequest);
        }
        body.put("person", personMap);

        HttpEntity<Map<String, Object>> httpEntity = createBackendHttpEntity(body);

        LOG.debug("Returning registration result to broker");
        try {
            ResponseEntity<Map<String, Object>> results = restTemplate.exchange(backendConfiguration.getUrl(), HttpMethod.POST, httpEntity, mapRef);
            int code = (int) results.getBody().getOrDefault("code", 400);
            if (code >= 400) {
                //Body can be immutable
                Map<String, Object> copy = new HashMap<>(results.getBody());
                copy.put("reference", referenceCorrelation());
                LOG.error(String.format("Error in registration results %s for enrollmentRequest %s", copy, enrollmentRequest));
                return ResponseEntity.ok(copy);
            }
            return ResponseEntity.status(code).body(results.getBody());
        } catch (HttpStatusCodeException e) {
            return this.errorResponseEntity("Error in registration results for enrollmentRequest: " + enrollmentRequest, e);
        }
    }

    private String referenceCorrelation() {
        return String.valueOf(Math.round(Math.random() * 10000));
    }

    /*
     * Called by the Broker on behalf of the test user
     */
    @Operation(summary = "Test results",
            description = "Called by the Broker on behalf of the test user.")
    @PostMapping("/api/play-results")
    public ResponseEntity<Map<String, Object>> playResults(@RequestHeader("X-Correlation-ID") String correlationId,
                                                           @RequestBody Map<String, Object> results) {
        if (!allowPlayground) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).orElseThrow(ExpiredEnrollmentRequestException::new);
        Map<String, Object> newResults = new HashMap<>(results);
        if (this.eduIDRequired) {
            newResults.put("personId", enrollmentRequest.getEduid());
        }
        Association association;
        if (results.containsKey("associationId")) {
            association = associationRepository.findByAssociationId((String) results.get("associationId"))
                    .orElseThrow(ExpiredEnrollmentRequestException::new);
            return this.associationUpdate(association.getAssociationId(), newResults);
        } else if (results.containsKey("v4")) {
            return this.results(newResults);
        } else {
            return this.associate(enrollmentRequest.getEduid(), results);
        }
    }

    /*
     * Called by the SIS of the guest institution to inform the home institution of the new enrollment
     */
    @Operation(summary = "Proxy person information request",
            description = "Called by the SIS of the guest institution to inform the home institution of the new enrollment.")
    @PostMapping("/associations/external/{personId}")
    public ResponseEntity<Map<String, Object>> associate(@PathVariable("personId") String personId,
                                                         @RequestBody Map<String, Object> association) {
        EnrollmentRequest enrollmentRequest = getEnrollmentRequest(personId);

        LOG.debug(String.format("Associate endpoint called by SIS personId %s for enrolment request %s", personId, enrollmentRequest));

        String associationURI;
        try {
            associationURI = serviceRegistry.associationsURI(enrollmentRequest) + "/external/me";
        } catch (HttpStatusCodeException e) {
            return this.errorResponseEntity("Error in obtaining associationURI for enrolment request:" + enrollmentRequest, e);
        }
        LOG.debug(String.format("Posting association endpoint for personId %s and enrolment request %s to %s", personId, enrollmentRequest, associationURI));

        ResponseEntity<Map<String, Object>> responseEntity = exchangeToHomeInstitution(enrollmentRequest, association, associationURI, HttpMethod.POST, false, true);
        if (HttpStatus.CREATED.equals(responseEntity.getStatusCode())) {
            String associationId = (String) responseEntity.getBody().get("associationId");
            associationRepository.save(new Association(associationId, enrollmentRequest));
        }
        return ResponseEntity.status(responseEntity.getStatusCode()).body(responseEntity.getBody());
    }

    /*
     * Called by the SIS of the guest institution to inform the home institution of the status of the (pending)
     * enrollment
     */
    @Operation(summary = "Proxy associations update",
            description = "Called by the SIS of the guest institution to inform the home institution of the status of the (pending) enrollment.")
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "The association fields to update, including result data.",
            required = true,
            content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    examples = @ExampleObject(
                            name = "OOAPI v4 Patch Association Example",
                            summary = "Updating remote state and adding results",
                            value = "{\n" +
                                    "  \"remoteState\": \"associated\",\n" +
                                    "  \"result\": {\n" +
                                    "    \"state\": \"completed\",\n" +
                                    "    \"pass\": \"passed\",\n" +
                                    "    \"comment\": \"string\",\n" +
                                    "    \"score\": \"9\",\n" +
                                    "    \"resultDate\": \"2020-09-28\",\n" +
                                    "    \"weight\": 100\n" +
                                    "  }\n" +
                                    "}"
                    )
            )
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Association successfully updated"),
            @ApiResponse(responseCode = "404", description = "Association not found")
    })
    @PatchMapping("/associations/{associationId}")
    public ResponseEntity<Map<String, Object>> associationUpdate(@PathVariable("associationId") String associationId,
                                                                 @RequestBody Map<String, Object> association) {
        return doAssociationUpdate(associationId, Optional.of(association));
    }

    /*
     * Called by the SIS of the guest institution to query the home institution on the status of the (pending)
     * enrollment
     */
    @Operation(summary = "Proxy associations request",
            description = "Called by the SIS of the guest institution to query the home institution on the status of the (pending) enrollment.")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Successful response with association details",
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON_VALUE,
                            examples = @ExampleObject(
                                    name = "OOAPI v4 Association Example",
                                    summary = "A standard OOAPI v4 Association with results",
                                    value = "{\n" +
                                            "  \"associationId\": \"123e4567-e89b-12d3-a456-426614174000\",\n" +
                                            "  \"associationType\": \"componentOfferingAssociation\",\n" +
                                            "  \"role\": \"student\",\n" +
                                            "  \"state\": \"associated\",\n" +
                                            "  \"remoteState\": \"associated\",\n" +
                                            "  \"person\": \"05035972-0619-4d0b-8a09-7bdb6eee5e6d\",\n" +
                                            "  \"offering\": \"811aede5-3f86-4ee8-bd58-925df0b0509d\",\n" +
                                            "  \"result\": {\n" +
                                            "    \"state\": \"completed\",\n" +
                                            "    \"pass\": \"passed\",\n" +
                                            "    \"score\": \"9\",\n" +
                                            "    \"resultDate\": \"2020-09-28\",\n" +
                                            "    \"weight\": 100\n" +
                                            "  }\n" +
                                            "}"
                            )
                    )
            ),
            @ApiResponse(responseCode = "404", description = "Association not found")
    })
    @GetMapping("/associations/{associationId}")
    public ResponseEntity<Map<String, Object>> associationUpdateGet(@PathVariable("associationId") String associationId) {
        return doAssociationUpdate(associationId, Optional.empty());
    }

    private ResponseEntity<Map<String, Object>> doAssociationUpdate(String associationId, Optional<Map<String, Object>> association) {
        EnrollmentRequest enrollmentRequest = associationRepository.findByAssociationId(associationId)
                .orElseThrow(ExpiredEnrollmentRequestException::new).getEnrollmentRequest();

        LOG.debug(String.format("Association update endpoint called by SIS for enrolment request %s", enrollmentRequest));

        String associationURI;
        try {
            associationURI = serviceRegistry.associationsURI(enrollmentRequest) + "/" + associationId;
        } catch (HttpStatusCodeException e) {
            return this.errorResponseEntity("Error in obtaining associationURI for enrolment request:" + enrollmentRequest, e);
        }
        LOG.debug(String.format("Patching association endpoint for enrolment request %s to %s", enrollmentRequest, associationURI));

        Map<String, Object> body = association.map(ass -> EnrollmentAssociation.transform(ass, enrollmentRequest)).orElse(null);
        HttpMethod httpMethod = association.map(ass -> HttpMethod.PATCH).orElse(HttpMethod.GET);
        return exchangeToHomeInstitution(enrollmentRequest, body, associationURI, httpMethod, false, true);
    }

    /*
     * Called by the SIS of the guest institution to report back results that need to be sent with oauth secured
     * to the home institution. V4 version for backward compatibility.
     */
    @Operation(summary = "Proxy result (deprecated)",
            description = "Called by the SIS of the guest institution to send the result to the home institution. Deprecated: Use /associations/{associationId} instead. ")
    @PostMapping("/api/results")
    public ResponseEntity<Map<String, Object>> results(@RequestBody Map<String, Object> results) {
        String personId = (String) results.get("personId");
        EnrollmentRequest enrollmentRequest = getEnrollmentRequest(personId);

        LOG.debug(String.format("Report back results endpoint called by SIS personId %s and enrolment request %s", personId, enrollmentRequest));

        String resultsURI;
        try {
            resultsURI = serviceRegistry.associationsURI(enrollmentRequest) + "/me";
        } catch (HttpStatusCodeException e) {
            return this.errorResponseEntity("Error in obtaining resultsURI for enrolment request:" + enrollmentRequest, e);
        }
        LOG.debug(String.format("Posting back results endpoint for personId %s and enrolment request %s to %s", personId, enrollmentRequest, resultsURI));

        Map<String, Object> body = EnrollmentAssociation.transform(results, enrollmentRequest);
        return exchangeToHomeInstitution(enrollmentRequest, body, resultsURI, HttpMethod.POST, true, true);
    }

    /*
     * Called by the playground
     */
    @Operation(summary = "Playground person information",
            description = "Used by the broker's playground.")
    @GetMapping("/api/me")
    public ResponseEntity<Map<String, Object>> me(@RequestHeader("X-Correlation-ID") String correlationId) {
        if (!allowPlayground) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).orElseThrow(ExpiredEnrollmentRequestException::new);
        return person(enrollmentRequest.getEduid());
    }

    /*
     * Called by the SIS of the guest institution to validate the status of a guest-user
     */
    @Operation(summary = "Proxy person request",
            description = "Called by the SIS of the guest institution to get the person information. Used for checking is the person is still active.")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Successful response with person details",
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON_VALUE,
                            examples = @ExampleObject(
                                    name = "OOAPI v4 Person Example",
                                    summary = "A standard OOAPI v4 Person response",
                                    value = "{\n" +
                                            "  \"personId\": \"123e4567-e89b-12d3-a456-426614174000\",\n" +
                                            "  \"primaryCode\": {\n" +
                                            "    \"codeType\": \"identifier\",\n" +
                                            "    \"code\": \"1234qwe12\"\n" +
                                            "  },\n" +
                                            "  \"givenName\": \"Maartje\",\n" +
                                            "  \"surnamePrefix\": \"van\",\n" +
                                            "  \"surname\": \"Damme\",\n" +
                                            "  \"displayName\": \"Maartje van Damme\",\n" +
                                            "  \"initials\": \"MCW\",\n" +
                                            "  \"activeEnrollment\": false,\n" +
                                            "  \"dateOfBirth\": \"2003-09-30\",\n" +
                                            "  \"cityOfBirth\": \"Utrecht\",\n" +
                                            "  \"countryOfBirth\": \"NL\",\n" +
                                            "  \"nationality\": \"Dutch\",\n" +
                                            "  \"dateOfNationality\": \"2003-09-30\",\n" +
                                            "  \"affiliations\": [ \"student\" ],\n" +
                                            "  \"mail\": \"vandamme.mcw@universiteitvanharderwijk.nl\",\n" +
                                            "  \"secondaryMail\": \"poekie@xyz.nl\",\n" +
                                            "  \"telephoneNumber\": \"+31 123 456 789\",\n" +
                                            "  \"mobileNumber\": \"+31 612 345 678\",\n" +
                                            "  \"photoSocial\": \"https://upload.wikimedia.org/wikipedia/commons/thumb/d/d5/Placeholder_female_superhero_c.png/203px-Placeholder_female_superhero_c.png\",\n" +
                                            "  \"photoOfficial\": \"https://upload.wikimedia.org/wikipedia/commons/6/66/Johannes_Vermeer_%281632-1675%29_-_The_Girl_With_The_Pearl_Earring_%281665%29.jpg\",\n" +
                                            "  \"gender\": \"F\",\n" +
                                            "  \"titlePrefix\": \"drs\",\n" +
                                            "  \"titleSuffix\": \"BSc\",\n" +
                                            "  \"address\": {\n" +
                                            "    \"addressType\": \"postal\",\n" +
                                            "    \"street\": \"Moreelsepark\",\n" +
                                            "    \"streetNumber\": \"48\",\n" +
                                            "    \"postalCode\": \"3511 EP\",\n" +
                                            "    \"city\": \"Utrecht\",\n" +
                                            "    \"countryCode\": \"NL\"\n" +
                                            "  }\n" +
                                            "}"
                            )
                    )
            ),
            @ApiResponse(responseCode = "404", description = "Person not found")
    })
    @GetMapping("/person/{personId}")
    public ResponseEntity<Map<String, Object>> person(@PathVariable("personId") String personId) {
        EnrollmentRequest enrollmentRequest = getEnrollmentRequest(personId);

        LOG.debug(String.format("Person endpoint called by SIS for enrolment request %s", enrollmentRequest));

        String personURI;
        try {
            personURI = serviceRegistry.personsURI(enrollmentRequest);
        } catch (HttpStatusCodeException e) {
            return this.errorResponseEntity("Error in obtaining personURI for enrolment request:" + enrollmentRequest, e);
        }
        LOG.debug(String.format("Getting person endpoint for enrolment request %s to %s", enrollmentRequest, personURI));

        ResponseEntity<Map<String, Object>> responseEntity = exchangeToHomeInstitution(enrollmentRequest, null, personURI, HttpMethod.GET, true, true);
        if (responseEntity.getStatusCode().is2xxSuccessful()) {
            responseEntity.getBody().put("personId", enrollmentRequest.getEduid());
        }
        return ResponseEntity.status(responseEntity.getStatusCode()).body(responseEntity.getBody());
    }

    private EnrollmentRequest getEnrollmentRequest(String personId) {
        List<EnrollmentRequest> enrollmentRequests = enrollmentRepository.findByEduidOrderByCreatedDesc(personId);
        if (CollectionUtils.isEmpty(enrollmentRequests)) {
            LOG.error("Enrollment not found for: " + personId);
            throw new ExpiredEnrollmentRequestException();
        }
        return enrollmentRequests.get(0);
    }

    private ResponseEntity<Map<String, Object>> exchangeToHomeInstitution(EnrollmentRequest enrollmentRequest,
                                                                          Map<String, Object> body,
                                                                          String uri,
                                                                          HttpMethod httpMethod,
                                                                          boolean returnHttpStatusOk,
                                                                          boolean retry) {

        var refreshAccessToken = !retry;
        String accessToken = null;

        try{
            accessToken = resolveAccessToken(enrollmentRequest, refreshAccessToken);
        } catch (HttpStatusCodeException e2) {
            return this.errorResponseEntity("Error in obtaining new accessToken with saved refreshToken for enrolment request:" + enrollmentRequest, e2);
        }

        HttpHeaders httpHeaders = getOidcAuthorizationHttpHeaders(
                accessToken,
                PersonAuthentication.HEADER.name()
        );
        HttpEntity<Map<String, Object>> requestEntity = new HttpEntity(body, httpHeaders);

        try {
            ResponseEntity<Map<String, Object>> exchanged = restTemplate.exchange(uri, httpMethod, requestEntity, mapRef);

            LOG.debug(String.format("Received answer from %s with status %s", uri, exchanged.getStatusCode()));

            return ResponseEntity.status(returnHttpStatusOk ? HttpStatus.OK : exchanged.getStatusCode())
                    .body(exchanged.getBody());
        } catch (HttpStatusCodeException e) {
            if (retry) {
                return exchangeToHomeInstitution(enrollmentRequest, body, uri, httpMethod, returnHttpStatusOk, false);
            } else {
                return this.errorResponseEntity(String.format("Error %s from the OOAPI endpoint %s for enrolment request: %s.",
                        e.getStatusCode(),
                        uri,
                        enrollmentRequest), e);
            }
        }
    }

    private ResponseEntity<Map<String, Object>> errorResponseEntity(String description, HttpStatusCodeException e) {
        String reference = referenceCorrelation();
        LOG.error(String.format("%s, reference: %s", description, reference), e);

        Map<String, Object> results = new HashMap<>();
        results.put("error", true);
        results.put("reference", reference);
        results.put("message", e.getMessage());
        results.put("details", e.getResponseBodyAsString());
        results.put("description", description);
        results.put("status", e.getStatusCode());
        //Preserve the status from the Exception
        return ResponseEntity.status(e.getStatusCode()).body(results);
    }

    private Map<String, Object> person(EnrollmentRequest enrollmentRequest) {
        String personAuth = enrollmentRequest.getPersonAuth();
        String accessToken = resolveAccessToken(enrollmentRequest);
        HttpHeaders httpHeaders = getOidcAuthorizationHttpHeaders(accessToken, personAuth);

        LOG.debug("Retrieve person information from : " + enrollmentRequest.getPersonURI() + " using personAuth; " + personAuth);

        if (personAuth.equalsIgnoreCase(PersonAuthentication.FORM.name())) {
            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("access_token", accessToken);
            HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(map, httpHeaders);
            return restTemplate.exchange(enrollmentRequest.getPersonURI(), HttpMethod.POST, requestEntity, mapRef).getBody();
        } else {
            HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(httpHeaders);
            return restTemplate.exchange(enrollmentRequest.getPersonURI(), HttpMethod.GET, requestEntity, mapRef).getBody();
        }
    }

    private HttpHeaders getOidcAuthorizationHttpHeaders(String accessToken, String personAuth) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Accept", "application/json, application/json;charset=UTF-8");
        if (personAuth.equalsIgnoreCase(PersonAuthentication.FORM.name())) {
            httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        } else {
            httpHeaders.setBearerAuth(accessToken);
        }
        return httpHeaders;
    }

    private String buildAuthorizationURI(EnrollmentRequest enrollmentRequest) throws IOException {
        Map<String, String> params = new HashMap<>();
        String base64Enrollment = enrollmentRequest.serializeToBase64(objectMapper);

        List<ClaimsSetRequest.Entry> entries = Stream.of(
                "family_name",
                "given_name",
                "eduid")
                .filter(claimValue -> this.eduIDRequired || !claimValue.equals("eduid"))
                .map(ClaimsSetRequest.Entry::new)
                .toList();
        params.put("claims", new OIDCClaimsRequest().withIDTokenClaimsRequest(new ClaimsSetRequest(entries)).toJSONString());
        if (!"noop".equalsIgnoreCase(acr)) {
            params.put("acr_values", acr);
        }
        params.put("scope", "openid " + enrollmentRequest.getScope());
        params.put("client_id", clientId);
        params.put("response_type", "code");
        params.put("redirect_uri", redirectUri);
        params.put("state", base64Enrollment);
        //When working outside of Openconnext, the 'offline_access' is added for refresh tokens,
        // and 'prompt=consent' should be added
        if (enrollmentRequest.getScope().contains("offline_access")) {
            params.put("prompt", "consent");
        }

        UriComponentsBuilder builder = UriComponentsBuilder.fromUri(authorizationUri);
        params.forEach(builder::queryParam);
        return builder.build().encode().toUriString();
    }

    @SneakyThrows
    private void validateServiceRegistryEndpoints(EnrollmentRequest enrollmentRequest) {
        LOG.debug(String.format("Calling validate enrollmentRequest with %s", enrollmentRequest));
        Map<String, Boolean> results = serviceRegistry.validate(enrollmentRequest);
        if (!(boolean) results.get("valid")) {
            throw new IllegalArgumentException(
                    String.format("Invalid URI's for enrolment %s provided reported by %s",
                            enrollmentRequest, this.serviceRegistry.getServiceRegistryBaseURL()));
        }
    }

    private String resolveAccessToken(EnrollmentRequest enrollmentRequest) {
        return resolveAccessToken(enrollmentRequest, false);
    }

    private String resolveAccessToken(EnrollmentRequest enrollmentRequest, boolean forceRefresh){
        if(forceRefresh){
            accessTokenCache.invalidate(enrollmentRequest.getIdentifier());
        }

        return accessTokenCache.get(enrollmentRequest.getIdentifier(), key -> {
            LOG.debug("Obtaining new accessToken with saved refreshToken for enrolment request: " + enrollmentRequest);

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("client_id", clientId);
            map.add("client_secret", clientSecret);
            map.add("grant_type", "refresh_token");
            map.add("refresh_token", enrollmentRequest.getRefreshToken());

            Map<String, Object> oidcResponse = tokenRequest(map);
            String accessToken = (String) oidcResponse.get("access_token");
            String refreshToken = (String) oidcResponse.get("refresh_token");

            enrollmentRequest.setRefreshToken(refreshToken);

            enrollmentRepository.save(enrollmentRequest);

            return accessToken;
        });
    }
}
