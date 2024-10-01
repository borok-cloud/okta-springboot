package com.mars.demoOkata;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class CustomOidcUserService extends OidcUserService {

    @Override
    public OidcUser loadUser(OidcUserRequest oidcUserRequest) {
        // Delegate to the default implementation for loading the OIDC user
        OidcUser oidcUser = super.loadUser(oidcUserRequest);
        OAuth2AccessToken token = oidcUserRequest.getAccessToken();
        //get the groups from the token
        // Fetch or manipulate authorities (roles, permissions, etc.)
        Set<GrantedAuthority> mappedAuthorities = new HashSet<>(oidcUser.getAuthorities());

        // Example: Add a custom role to the user
        mappedAuthorities.add(new SimpleGrantedAuthority("Admin"));

        // Create a new OidcUser with custom authorities
        return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
    }
}
