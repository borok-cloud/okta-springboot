package com.mars.demoOkata;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        // Extract roles from the JWT claims
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        return new JwtAuthenticationToken(jwt, authorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        // Replace "roles" with the claim name where your roles are stored
        //List<String> roles = jwt.getClaimAsStringList("roles");
        List<String> roles = jwt.getClaimAsStringList("groups");

        if (roles == null || roles.isEmpty()) {
            return Collections.emptyList();
        }
        List<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role)) // Prefix with "ROLE_"
                .collect(Collectors.toList());
        System.out.println(" Granted Authorities: ");
        authorities.forEach(System.out::println);
        return authorities;
    }
}
