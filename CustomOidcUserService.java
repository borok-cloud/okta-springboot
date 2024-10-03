package com.mars.demoOkata;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class CustomOidcUserService extends OidcUserService {

    private final JwtDecoder jwtDecoder;

    public CustomOidcUserService(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest oidcUserRequest) {
        // Delegate to the default implementation for loading the OIDC user
        OidcUser oidcUser = super.loadUser(oidcUserRequest);
        OAuth2AccessToken accessToken = oidcUserRequest.getAccessToken();
        //get the groups from the token
        // Fetch or manipulate authorities (roles, permissions, etc.)
        // Extract the Okta groups from the token claims
        List<String> oktaGroups = oidcUser.getAttribute("groups");
        // Decode the access token to extract claims
        Jwt decodedToken = jwtDecoder.decode(accessToken.getTokenValue());

        // Extract groups from the token
        List<String> groups = decodedToken.getClaimAsStringList("groups");

        // Map groups to Spring Security authorities
        Set<GrantedAuthority> authorities = groups.stream()
                //.map(group -> new SimpleGrantedAuthority("ROLE_" + group))
                .map(group -> new SimpleGrantedAuthority(group))
                .collect(Collectors.toSet());

        Set<GrantedAuthority> mappedAuthorities = new HashSet<>(oidcUser.getAuthorities());
        mappedAuthorities.addAll(authorities);

        // Example: Add a custom role to the user
        //mappedAuthorities.add(new SimpleGrantedAuthority("Admin"));

        // Create a new OidcUser with custom authorities
        return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
    }
}
