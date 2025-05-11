package com.example.orquestador.Config;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.core5.util.Timeout;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity; // Para Gateway MVC
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;
import org.slf4j.Logger; // Importa Logger
import org.slf4j.LoggerFactory;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebSecurity // Para Spring Security con el stack Servlet (usado por Gateway MVC)
public class GatewaySecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(GatewaySecurityConfig.class); // Logger

    @Value("${jwt.secret}")
    private String jwtSecretString;

    @Value("${app.cors.frontend-url}")
    private String frontendAppUrl;

    // Método para obtener la clave, igual que antes
    private SecretKey getSigningKey() {
        logger.debug("Attempting to decode JWT secret string...");
        byte[] keyBytes = this.jwtSecretString.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (keyBytes.length * 8 < 256) { // Verifica la longitud en bits
            logger.error("CRITICAL: JWT secret key is too short! Length (bits): {}. MUST be >= 256 bits.", keyBytes.length * 8);
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        logger.info("Creating NimbusJwtDecoder bean with symmetric secret key.");
        SecretKey secretKey = getSigningKey();
        return NimbusJwtDecoder.withSecretKey(secretKey).build();
    }

    @Bean
    public ClientHttpRequestFactory clientHttpRequestFactory() {
        // Configura el Connection Manager para el pooling
        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(200); // Máximo total de conexiones
        connectionManager.setDefaultMaxPerRoute(50); // Máximo de conexiones por ruta

        // Configura los timeouts y otras propiedades del request
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(Timeout.ofSeconds(5)) // Timeout para obtener una conexión del pool
                .setConnectTimeout(Timeout.ofSeconds(5))           // Timeout para establecer la conexión
                // .setResponseTimeout(Timeout.ofSeconds(30))      // Timeout para esperar datos (Apache HttpClient 5)
                // En versiones anteriores era socket timeout
                .setExpectContinueEnabled(false) // <--- ¡INTENTA DESHABILITAR ESTO!
                .build();

        // Construye el HttpClient
        CloseableHttpClient httpClient = HttpClientBuilder.create()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(requestConfig)
                .disableAutomaticRetries() // Opcional: deshabilita reintentos automáticos
                // .disableRedirectHandling() // Opcional: deshabilita manejo de redirecciones
                .build();

        // Crea la fábrica usando el HttpClient configurado
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);
        // factory.setReadTimeout(30000); // Otra forma de setear el socket/read timeout
        return factory;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Deshabilitar CSRF (común para APIs stateless)
                .csrf(csrf -> csrf.disable())
                // Configurar la gestión de sesiones como STATELESS
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Configurar las reglas de autorización
                .authorizeHttpRequests(authorize -> authorize
                        // Rutas públicas:
                        // - El endpoint de login/registro de tu AuthService (a través del Gateway)
                        .requestMatchers("/auth/register/**","/auth/login", "/auth/admin/**").permitAll()
                        // - Si AuthService expone JWK Set URI, hacerlo público
                        .requestMatchers("/.well-known/jwks.json").permitAll() // Si tu auth service lo expone en su raíz
                        // - Documentación de la API del Gateway (si la tienes)
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/**").permitAll()
                        // - Cualquier otra ruta requiere autenticación
                        .anyRequest().authenticated()
                )
                // Configurar el Gateway para actuar como un OAuth2 Resource Server y validar JWTs
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> {
                }));

        return http.build();
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**") // Permite todas las rutas
                        .allowedOriginPatterns(
                                "http://localhost:[*]", // Permite cualquier puerto en localhost
                                frontendAppUrl // Permite cualquier subdominio
                        )
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*")
                        .allowCredentials(true); // Permitir cookies y credenciales
            }
        };
    }
}

