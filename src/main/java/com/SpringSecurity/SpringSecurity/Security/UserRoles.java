package com.SpringSecurity.SpringSecurity.Security;

import com.google.common.collect.Sets;

import java.util.Set;

public enum UserRoles {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(Permissions.COURSE_READ, Permissions.COURSE_WRITE, Permissions.STUDENT_READ, Permissions.STUDENT_WRITE));

    private final Set<Permissions> permissions;

    UserRoles(Set<Permissions> permissions){
        this.permissions = permissions;
    }
}
