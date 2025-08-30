package laughcandidate.yellowribbonbe.auth.filter;

import java.io.IOException;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.GenericFilterBean;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import laughcandidate.yellowribbonbe.auth.jwt.TokenProvider;
import laughcandidate.yellowribbonbe.auth.util.ResponseUtil;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilterBean {

    private static final String LOGOUT_URL = "/auth/logout";

    private final TokenProvider tokenProvider;
    private final ObjectMapper objectMapper;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {

        if (!request.getRequestURI().equals(LOGOUT_URL) || !HttpMethod.POST.matches(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = tokenProvider.resolveAccessToken(request);
        Claims claimsByAccessToken = tokenProvider.getClaimsFromToken(accessToken);
        String uid = claimsByAccessToken.getSubject();

        tokenProvider.deleteRefreshToken(uid);
        tokenProvider.deleteUserId(uid);

        ResponseUtil.writeNoContent(
                response,
                objectMapper,
                HttpStatus.OK
        );
    }
}