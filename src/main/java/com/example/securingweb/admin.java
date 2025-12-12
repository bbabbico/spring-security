package com.example.securingweb;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class admin {
    @GetMapping("/admin")
    public String admin1(){
        return "admin";
    }
}
