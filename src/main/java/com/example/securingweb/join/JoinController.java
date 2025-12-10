package com.example.securingweb.join;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@RequiredArgsConstructor
@Controller
public class JoinController {

    private final JoinService joinService;


    @GetMapping("/join")
    public String joinP() {

        return "join";
    }


    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO) {

        System.out.println(joinDTO.getUsername());

        joinService.joinProcess(joinDTO);


        return "redirect:/login";
    }
}
