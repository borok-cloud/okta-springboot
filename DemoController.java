package com.mars.demoOkata;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins = "http://localhost:4200")
//@PreAuthorize("isAuthenticated()")
public class DemoController {

    @GetMapping("/")
   // @PreAuthorize("permitAll()")
    public ResponseEntity<String> greetingUser(){
        return new ResponseEntity<>("Welcome home!", HttpStatus.OK);
    }

    @GetMapping("/restricted")
    @PreAuthorize("hasAnyAuthority('Admin','ROLE_ADMIN')")
    public ResponseEntity<String> restricted(){
        return new ResponseEntity<>("You found the secret lair!", HttpStatus.OK);
    }

    @GetMapping("/api/messages")
    @PreAuthorize("hasAnyAuthority('Admin','ROLE_ADMIN')")
    public Map<String, Object> messages() {

        Map<String, Object> result = new HashMap<>();
        result.put("messages", Arrays.asList(
                new Message("I am a robot."),
                new Message("Hello, world!")
        ));

        return result;
    }
}
