package com.mars.demoOkata;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
//@PreAuthorize("isAuthenticated()")
public class DemoController {

    @GetMapping("/")
   // @PreAuthorize("permitAll()")
    public ResponseEntity<String> greetingUser(){
        return new ResponseEntity<>("Welcome home!", HttpStatus.OK);
    }

    @GetMapping("/restricted")
    @PreAuthorize("hasAuthority('Admin')")
    public ResponseEntity<String> restricted(){
        return new ResponseEntity<>("You found the secret lair!", HttpStatus.OK);
    }
}
