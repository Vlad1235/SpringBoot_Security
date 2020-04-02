package com.example.springspringbootsecurity.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.example.springspringbootsecurity.security.ApplicationPermissions.*;

/**
 * Тут будут прописаны все роли, которые присутствуют в данном приложении.
 * Также сразу присвоены разрешения к каждой из ролей.
 */
public enum ApplicationRoles {
    STUDENT(Sets.newHashSet()), // нет никаких разрешений для данной роли
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ)); // у данной роли будут лишь разрешения на чтение

    private final Set<ApplicationPermissions> permissions;

    ApplicationRoles(Set<ApplicationPermissions> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationPermissions> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> grantedAuthorities() {
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }
}
