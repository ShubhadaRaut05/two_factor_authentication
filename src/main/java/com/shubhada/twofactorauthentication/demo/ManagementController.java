package com.shubhada.twofactorauthentication.demo;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/management")
//this should be only accessible only by manager and admin
public class ManagementController {

    @GetMapping
    public String get()
    {
        return "GET:: management controller";
    }

    @PostMapping
    public String post()
    {
        return "POST:: management controller";
    }

    @PutMapping
    public String put()
    {
        return "PUT:: management controller";
    }

    @DeleteMapping
    public String delete()
    {
        return "DELETE:: management controller";
    }
}
