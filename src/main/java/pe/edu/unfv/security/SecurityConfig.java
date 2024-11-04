package pe.edu.unfv.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authHttp -> authHttp
                .requestMatchers(HttpMethod.GET, "/authorized").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/students", "/api/courses").hasAnyAuthority("SCOPE_read", "SCOPE_write")
                .requestMatchers(HttpMethod.GET, "/api/students/{id}", "/api/courses/{id}").hasAuthority("SCOPE_write")
                .requestMatchers(HttpMethod.POST, "/api/students", "/api/courses").hasAuthority("SCOPE_write")
                .requestMatchers(HttpMethod.PUT, "/api/students/{id}", "/api/courses/{id}",
                        "/api/courses/{courseId}/student/{studentId}").hasAuthority("SCOPE_write")
                .requestMatchers(HttpMethod.DELETE, "/api/students/{id}", "/api/courses/{id}",
                        "/api/courses/{courseId}/student/{studentId}").hasAuthority("SCOPE_write")
                .anyRequest().authenticated())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2Login(login -> login.loginPage("/oauth2/authorization/CursoArquitecturaHexagonal-Gateway"))
                .oauth2Client(withDefaults())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()));

        return http.build();
    }
}
