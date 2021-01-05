package com.liu.jcwork.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author:${USER}
 * @DATE:${DATE}
 * @description:
 */
@RestController
public class HomeController {

    @GetMapping("/home")
    public String home(){
        return "HELLO !!!!!";
    }
    @GetMapping("/admin/hello")
    public String adminhome(){
        return "HELLO !!!!!admin";
    }
    @GetMapping("/user/hello")
    public String userhome(){
        return "HELLO !!!!!user";
    }
}
