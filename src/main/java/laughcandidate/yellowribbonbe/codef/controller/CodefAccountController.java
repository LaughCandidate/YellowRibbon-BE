package laughcandidate.yellowribbonbe.codef.controller;

import io.swagger.v3.oas.annotations.tags.Tag;
import laughcandidate.yellowribbonbe.codef.dto.request.CodefAccountRegisterRequest;
import laughcandidate.yellowribbonbe.codef.dto.response.CodefAccountRegisterResponse;
import laughcandidate.yellowribbonbe.codef.service.CodefAccountService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@Tag(name = "codef 연동")
@RestController
@RequestMapping("/api/codef/account")
@RequiredArgsConstructor
public class CodefAccountController {

    private final CodefAccountService codefAccountService;

    @PostMapping("/register")
    public ResponseEntity<CodefAccountRegisterResponse> registerAccount(
            @Valid @RequestBody CodefAccountRegisterRequest request,
            @RequestParam(value = "production", defaultValue = "false") boolean isProduction) {
        
        CodefAccountRegisterResponse response = codefAccountService.registerAccount(request, isProduction);
        
        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/register/demo")
    public ResponseEntity<CodefAccountRegisterResponse> registerDemoAccount(
            @Valid @RequestBody CodefAccountRegisterRequest request) {
        
        return registerAccount(request, false);
    }
}