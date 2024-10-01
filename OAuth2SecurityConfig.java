package com.mars.demoOkata;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

/*
 * Security settings
 * 	- HTTP GET calls to /books/** requires fakebookapi.read scope
 * 	- HTTP POST call to /books require fakebookapi.admin scope
 * 	- tokens come in as JWT 
 * 	- No sessions created during requests (No JSESSIONID Cookie created)
 * 
 * CHANGE : With Spring Boot 3.0, we no longer need to extend WebSecurityConfigurerAdapter
 */
@Configuration
//@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class OAuth2SecurityConfig {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/").permitAll()  // Allow access to root
                        .anyRequest().authenticated()      // All other requests need authentication
                )
                //.oauth2Client(Customizer.withDefaults())  // Enable OAuth2 client functionality for authorization code flow
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .oidcUserService(new CustomOidcUserService())
                        )
                );  // Optionally enable JWT handling for OAuth2 resource servers

        return http.build();
    }

	// CHANGE : With Spring Boot 3.0, Create a SecurityFilterChain 
	//@Bean
    public SecurityFilterChain filterChain_old(HttpSecurity http) throws Exception {
        http
          .authorizeHttpRequests(authz -> authz
            .requestMatchers(HttpMethod.GET, "/okta/restricted/**").hasAuthority("SCOPE_fakebook.read")
            //.requestMatchers(HttpMethod.GET, "/okta/admin").hasAuthority("SCOPE_fakebook.admin")
            .anyRequest().authenticated())
//                .oauth2Login(oauth2 -> oauth2
//                        .userInfoEndpoint(userInfo -> userInfo
//                                .oidcUserService(new CustomOidcUserService())
//                        )
//                )
               // .oauth2ResourceServer(oauth2 -> oauth2.jwt());
          .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))//Default working
          .sessionManagement(sMgmt -> sMgmt.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

//          .oauth2ResourceServer(rsc -> rsc.jwt(jwtConfigurer ->
//                jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter())));


        return http.build();
	}

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("SCOPE");  // Read 'groups' claim from token
        //grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        // Since Okta groups already have the ROLE_ prefix, we don't need to add it manually
        grantedAuthoritiesConverter.setAuthorityPrefix("");  // No prefix needed

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }
}
