package com.daelim.model.domain

import jakarta.persistence.*

@Entity
@Table(name = "users")
data class User(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,
    val username: String,
    val password: String // 실제 사용 시 비밀번호는 해시 처리되어야 합니다.
)