package com.example.spring_boot_notes_app.model

import org.bson.types.ObjectId
import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.mapping.Document
import java.time.Instant

@Document("notes")
data class Note(
    val title: String,
    val content: String,
    val color: String,
    val createdAt: Instant,
    @Id val id: ObjectId = ObjectId.get()
)
