package com.shubhada.twofactorauthentication.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.shubhada.twofactorauthentication.models.Permission.*;

@RequiredArgsConstructor
public enum Role {
    //each role can have multiple permissions
    USER(Collections.emptySet()),
    ADMIN(
            Set.of(
                   ADMIN_READ,
                    ADMIN_UPDATE,
                    ADMIN_DELETE,
                    ADMIN_CREATE,
                    MANAGER_READ,
                    MANAGER_UPDATE,
                    MANAGER_DELETE,
                    MANAGER_CREATE
            )
    ),
    MANAGER(
            Set.of(
                    MANAGER_READ,
                    MANAGER_UPDATE,
                    MANAGER_DELETE,
                    MANAGER_CREATE
            )
    )
    ;
    @Getter
    private final Set<Permission> permissions;
    public List<SimpleGrantedAuthority> getAuthorities()
    {
       var authorities= getPermissions()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toList());
       //when we work with role make sure that "ROLE_"
       authorities.add(new SimpleGrantedAuthority("ROLE_"+  this.name()));//this.name is role
       return authorities;
    }

}
