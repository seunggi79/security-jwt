package com.study.security_jwt.service;

import com.study.security_jwt.dto.CustomUserDetails;
import com.study.security_jwt.entity.UserEntity;
import com.study.security_jwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //DB에서 조회
        UserEntity userData = userRepository.findByUsername(username);

        if (userData == null) {

            //UserDetails에 담아서 return하면 AutneticationManager가 검증 함
            throw new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username);
        }

        return new CustomUserDetails(userData);
    }
}