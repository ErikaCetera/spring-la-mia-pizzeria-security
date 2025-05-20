package org.lessons.java.spring_la_mia_pizzeria_crud.security;

import java.util.HashSet;
import java.util.Set;

import org.lessons.java.spring_la_mia_pizzeria_crud.model.Role;
import org.lessons.java.spring_la_mia_pizzeria_crud.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class DatabaseUserDetails implements UserDetails {

    private final Integer id;
    private final String username;
    private final String password;
    private final Set<GrantedAuthority> authorities;

    public DatabaseUserDetails(User user){
        this.id = user.getId();
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.authorities = new HashSet<GrantedAuthority>();

        //per ogni ruolo presente in user crea un relativo permesso con quel nome
        for(Role userRole : user.getRoles()){
            authorities.add(new SimpleGrantedAuthority(userRole.getName()));
        }

    }

    public Integer getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public Set<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    //non scade mai
    @Override
    public boolean isAccountNonExpired(){
        return true;
    }

    //non è mai bloccato
    @Override
    public boolean isAccountNonLocked(){
        return true;
    }

    // le credenziali non scadono
    @Override
    public boolean isCredentialsNonExpired(){
        return true;
    }

    //sempre abilitato
    @Override
    public boolean isEnabled(){
        return true;
    }

}
