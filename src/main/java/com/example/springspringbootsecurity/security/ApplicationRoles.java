package com.example.springspringbootsecurity.security;

import com.google.common.collect.Sets;
import java.util.Set;
import static com.example.springspringbootsecurity.security.ApplicationPermissions.*;

/**
 * Тут будут прописаны все роли, которые присутствуют в данном приложении.
 * Также сразу присвоены разрешения к каждой из ролей.
 */
public enum ApplicationRoles {
    STUDENT(Sets.newHashSet()), // нет никаких разрешений для данной роли
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE,STUDENT_READ,STUDENT_WRITE));

    private final Set<ApplicationPermissions> permissions;

    ApplicationRoles(Set<ApplicationPermissions> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationPermissions> getPermissions() {
        return permissions;
    }
}
