package com.SpringSecurity.SpringSecurity.Security;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

public enum UserRoles {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(Permissions.COURSE_READ, Permissions.COURSE_WRITE, Permissions.STUDENT_READ, Permissions.STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(Permissions.COURSE_READ, Permissions.STUDENT_READ));

    private final Set<Permissions> permissions;

    UserRoles(Set<Permissions> permissions){
        this.permissions = permissions;
    }

    public Set<Permissions> getPermissions(){
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthority(){
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermissions()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }
}
