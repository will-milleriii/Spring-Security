package com.SpringSecurity.SpringSecurity.Controller;

import com.SpringSecurity.SpringSecurity.Entity.Student;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class ManagementController {

    private static final List<Student> STUDENTS  = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Indiana Jones"),
            new Student(3, "Jason Bourne")
    );

    @GetMapping
    public List<Student> getAllStudents(){
        System.out.println("List Of All Students");
        return STUDENTS;
    }

    @PostMapping
    public void registerNewStudent(@RequestBody Student student){
        System.out.println("Registered New Student");
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    public void deleteStudent(@PathVariable("studentId") Integer studentId){
        System.out.println("Deleted Student");
        System.out.println(studentId);
    }

    @PutMapping(path = "{studentId}")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student){
        System.out.println("Updated Student");
        System.out.println(String.format("%s %s", studentId, student));

    }

}
