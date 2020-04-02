package com.example.springspringbootsecurity.controllers;

import com.example.springspringbootsecurity.model.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1,"James Bond"),
            new Student(2,"Maria Jones"),
            new Student(3,"Anna Smith")
    );
    // hasRole('ROLE_') hasAnyRole('ROLE_') hasAuthority('permission') hasAnyAuthority('permission')
    @GetMapping()
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMINTRAINEE')") // вместо прописания ролей в методе void configure(HttpSecurity http) использование аннотации. Более красивый способ.
    public List<Student> getAllStudents(){
        return STUDENTS;
    }

    @PostMapping()
    @PreAuthorize("hasAnyAuthority('student:write')") // вместо прописания разрешений в методе void configure(HttpSecurity http) использование аннотации. Более красивый способ.
    public void registerNewStudent(@RequestBody Student student){
        System.out.println(student);
    }

    @DeleteMapping(path="{studentId}")
    @PreAuthorize("hasAnyAuthority('student:write')") // вместо прописания разрешений в методе void configure(HttpSecurity http) использование аннотации. Более красивый способ.
    public void deleteStudent(@PathVariable("studentId") Integer studentId){
        System.out.println(studentId);
    }

    @PutMapping(path="{studentId}")
    @PreAuthorize("hasAnyAuthority('student:write')") // вместо прописания разрешений в методе void configure(HttpSecurity http) использование аннотации. Более красивый способ.
    public void updateStudent(@PathVariable("studentId") Integer studentId, Student student){
        System.out.println(String.format("%s %s",student, studentId));
    }
}
