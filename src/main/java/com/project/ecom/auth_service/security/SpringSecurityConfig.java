package com.project.ecom.auth_service.security;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import com.project.ecom.auth_service.security.ropc.OAuth2PasswordAuthenticationConverter;
import com.project.ecom.auth_service.security.ropc.OAuth2PasswordAuthenticationProvider;
import com.project.ecom.auth_service.security.services.CustomUserDetailsService;
import com.project.ecom.auth_service.strategies.OAuth2TokenGenerationStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import javax.crypto.spec.SecretKeySpec;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig {
    /*
    classic issue: CSRF protection interfering with stateless API access using a bearer token.

    >> What's Happening
    You're sending a Bearer <access-token> in the Authorization header (which is correct for OAuth2), but Spring Security's CSRF protection is still active, and it's rejecting your request because it's a POST without a CSRF token.
    This is normal behavior when CSRF protection is enabled and sessions are used — which isn't the case for OAuth2 resource servers, where everything is stateless.

    >> Why disable CSRF for APIs?
    CSRF is only required for cookie-based session authentication (like browser logins).
    If you're using OAuth2 Bearer tokens in Authorization header, you're already protected.
    So CSRF is redundant and counterproductive for stateless APIs.

    Meaning of: authorize.anyRequest().authenticated()
    - Every HTTP request, regardless of its path or method, must be authenticated — i.e., the user must be logged in or present a valid token.

    >> Breakdown
    authorize — this is the authorization configuration block.
    .anyRequest() — matches all requests, including static assets (/css/**, /favicon.ico, etc.).
    .authenticated() — requires the request to be made by an authenticated principal (user or client).

    >> What it enforces
    It ensures that:
    For login-based flows: the user must be logged in via a form.
    For OAuth2: the client must send a valid Authorization: Bearer <token> header.

    If not, Spring Security:
    Redirects to the login page (for browser requests), or
    Returns 401 Unauthorized (for API requests with missing/invalid tokens).

    >> Common Alternatives
    Code	Meaning
    .permitAll()	Allow access to this request path without authentication.
    .denyAll()	Deny all access — return 403 for everyone.
    .hasRole("ADMIN")	Allow access only if the authenticated user has the ROLE_ADMIN authority.
    .hasAuthority("SCOPE_read")	Used in OAuth2 to check for scopes in JWT.

    >> Example
    http
      .authorizeHttpRequests(authorize -> authorize
          .requestMatchers("/public/**").permitAll()
          .requestMatchers("/admin/**").hasRole("ADMIN")
          .anyRequest().authenticated()
      );
    /public/** → open to everyone.
    /admin/** → only accessible to users with ROLE_ADMIN.
    Everything else → requires login or token.

     */

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager, OAuth2AuthorizationService oAuth2AuthorizationService, OAuth2TokenGenerator<?> tokenGenerator, OAuth2TokenGenerationStrategy oAuth2TokenGenerationStrategy)
            throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        // Step 2: Register Password Grant support: ROPC (Resource Owner Password Credentials)
        authorizationServerConfigurer
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .accessTokenRequestConverters(converters -> {
                            // Support parsing password grant requests
                            converters.add(new OAuth2PasswordAuthenticationConverter());
                        })
                        .authenticationProviders(providers -> {
                            // Handle authentication and token generation for password grant
                            providers.add(new OAuth2PasswordAuthenticationProvider(
                                    authenticationManager,
                                    oAuth2AuthorizationService,
                                    tokenGenerator,
                                    oAuth2TokenGenerationStrategy
                            ));
                        }));

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                .oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
                )
                .authorizeHttpRequests((authorize) ->
                        authorize
                                .anyRequest().authenticated()
                )
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );

        return http.build();
    }

    // Created for public endpoints for which no auth token is required
    @Bean
    @Order(2)
    SecurityFilterChain publicSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/api/auth/public/**"),
                        new AntPathRequestMatcher("/api/users/login"),
                        new AntPathRequestMatcher("/api/users/reset-password"),
                        new AntPathRequestMatcher("/api/users/reset-password/confirm")
                ))  // only matches public apis (requires no auth token)
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll()
                )
                .csrf(csrf -> csrf.disable());
        return http.build();  // No OAuth2ResourceServer here
    }

    /*
    >> Issue
    Your defaultSecurityFilterChain is treating all requests (including API endpoints) as stateful form login-based requests and does not disable CSRF, which breaks stateless requests authenticated via Authorization: Bearer.

    >> What to Fix
    You need to update your defaultSecurityFilterChain to:
    Disable CSRF for stateless endpoints (e.g., /api/**).
    Enable OAuth2 Resource Server support (so it validates JWTs or opaque tokens).

    >> Issue
    Authorization token (if passed) is still being validated for permitted requests (signup and login)

    Reason:
    permitAll() only affects authorization.
    But the Bearer-token authentication filter runs before authorization; if it sees an Authorization: Bearer … header it must try to validate it.

    >> Fix:
    To ignore any Bearer token on selected paths you have two good options.
    1) Put the public endpoints in their own filter-chain (simplest)
    2) Keep one chain and use a custom BearerTokenResolver

    // — chain for SIGN-UP / LOGIN ——————————————————————————
    @Bean @Order(1)
    SecurityFilterChain authEndpoints(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/auth/**")        // <-- match only these paths
            .authorizeHttpRequests(a -> a.anyRequest().permitAll())
            ...
    }

    // — chain for everything else ————————————————————————
    @Bean @Order(2)
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
            ...
    }

    OR, plugin a custom bearer token resolver

    @Bean
    BearerTokenResolver customBearerTokenResolver() {
        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        return request -> {
            String path = request.getRequestURI();
            if (path.startsWith("/api/auth")) {
                return null;
            }
            return resolver.resolve(request);
        };
    }

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http
            ...
            .oauth2ResourceServer(oauth2 -> oauth2
                .bearerTokenResolver(bearerTokenResolver())   // <- plug it in
                .jwt(jwt -> jwt.decoder(jwtDecoder()))
            ...
    }
     */
    @Bean
    @Order(3)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/api/**")  // DISABLE CSRF for REST APIs
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        // DISABLED: as it expects a spring generated JWT signed with RS256 (OAuth2 client)
                        // .jwt(Customizer.withDefaults())  // Enabling OAuth2 Resource Server, so that it validated JWT tokens

                        // Using custom jwt authentication converter
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))

                        // .jwt(jwt -> jwt.decoder(jwtDecoder()))  // For custom JJWT token
                );

        return http.build();
    }

    /* DISABLED in-memory user
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

     */

    /* EXPERIMENT: trying to check if {noop} encoder prefix works as in .clientSecret("{noop}secret")
    - Status: FAILED
        - Tried everything but could not make it work!
        - Using BCryptPasswordEncoder as the default password encoder

    >> When does {noop} work?
    {noop} only works if you're using a DelegatingPasswordEncoder which supports {noop} as a prefix.
    This DelegatingPasswordEncoder looks at the prefix ({noop}, {bcrypt}, etc.) and chooses the correct encoder.

     */
//    @Bean
//    @Order(3)  // Forcing passwordEncoder bean to be created before registeredClientRepository to ensure {noop} works
//    public PasswordEncoder defaultPasswordEncoder() {
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }


    /*
    Test with Browser:
    http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=oidc-client&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/oidc-client&scope=openid profile

    Test with Postman:
    Grant Type: Authorization Code
    Callback URL: https://oauth.pstmn.io/v1/callback
    Auth URL: http://127.0.0.1:8080/oauth2/authorize
    Access Token URL: http://127.0.0.1:8080/oauth2/token

     */
    /* DISABLED in-memory registeredClient
    @Bean
    @Order(4)
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("oidc-client")
                .clientSecret(passwordEncoder.encode("secret"))  // {noop} stands for "No Operation" for password encoding
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")  // Test with Browser
                .redirectUri("https://oauth.pstmn.io/v1/callback")  // Test with Postman
                .postLogoutRedirectUri("http://127.0.0.1:8080/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(oidcClient);
    }

     */

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    /*
    Addressing the below issue: Approach 1 - Creating a bean of PasswordEncoder (visible through the app context)
    java.lang.IllegalArgumentException: Given that there is no default password encoder configured, each password must have a password encoding prefix. Please either prefix this password with '{noop}' or set a default password encoder in .

    NOTE: BCryptPasswordEncoder doesn’t know what to do with {noop} — it expects a $2a$-style hash.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
    >> Issue
    BadJwtException: An error occurred while attempting to decode the Jwt: Signed JWT rejected: Another algorithm expected, or no matching key(s) found
    Since I am using JJWT token, spring has no idea about how to decode it when "OAuth2 Resource Server" is enabled
    .oauth2ResourceServer(oauth2 -> oauth2
        .jwt(Customizer.withDefaults())  // Expects spring generated JWT signed with RS256
    )

    >> Fix
    Add custom decoder bean: Decodes a JWT signed with HS256 (HMAC + secret) - generated using JJWT

     */
    JwtDecoder jwtDecoder() {
        byte[] secret = System.getenv("JWT_SECRET").getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKey = new SecretKeySpec(secret, "HmacSHA256");
        return NimbusJwtDecoder.withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
    }

    // Required so that spring can read the user roles (authorities) from the access token
    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new CustomJwtAuthenticationConverter());
        return converter;
    }

    // required for authenticating username and password (user credentials)
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // required by DelegatingOAuth2TokenGenerator
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /*
    @Bean
    public DaoAuthenticationProvider authenticationProvider(CustomUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationProvider authenticationProvider) {
        return new ProviderManager(authenticationProvider);
    }

     */
}