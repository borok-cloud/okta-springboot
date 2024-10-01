package com.mars.demoOkata;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RequestMapping("/user")
@RestController
public class UserController {

    @RequestMapping("/oauthinfo")
    @ResponseBody
    public String oauthUserInfo(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
                                @AuthenticationPrincipal OAuth2User oauth2User) {

        // Access the AccessToken
       // Jwt jwt = (Jwt) authorizedClient.getAccessToken().getTokenValue();

        // Extract groups from JWT claims
       // List<String> groups = jwt.getClaimAsStringList("groups");  // Assumes "groups" claim exists

        return
                "User Name: " + oauth2User.getName() + "<br/>" +
                        "User Authorities: " + oauth2User.getAuthorities() + "<br/>" +
                        "Client Name: " + authorizedClient.getClientRegistration().getClientName() + "<br/>" +
                        this.prettyPrintAttributes(oauth2User.getAttributes());
    }

    private String prettyPrintAttributes(Map<String, Object> attributes) {
        String acc = "User Attributes: <br/><div style='padding-left:20px'>";
        for (String key : attributes.keySet()){
            Object value = attributes.get(key);
            acc += "<div>"+key + ":&nbsp" + value.toString() + "</div>";
        }
        return acc + "</div>";
    }
}
