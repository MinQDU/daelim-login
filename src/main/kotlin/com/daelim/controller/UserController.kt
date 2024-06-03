package com.daelim.controller

import com.daelim.model.domain.User
import com.daelim.service.UserService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/users")
class UserController(
    private val userService: UserService
) {

    @PostMapping("/register")
    fun register(
        @RequestParam username: String,
        @RequestParam password: String
    ): ResponseEntity<User> {
        val user = userService.registerUser(username, password)
        return ResponseEntity.ok(user)
    }

    @PostMapping("/login")
    fun login(
        @RequestParam username: String,
        @RequestParam password: String
    ): ResponseEntity<String> {
        return if (userService.validateUser(username, password)) {
            ResponseEntity.ok(userService.login(username, password))
        } else {
            ResponseEntity.badRequest().body("Invalid credentials")
        }
    }
}