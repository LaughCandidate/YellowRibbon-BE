package laughcandidate.yellowribbonbe.product.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import laughcandidate.yellowribbonbe.auth.service.CustomUserDetails;
import laughcandidate.yellowribbonbe.product.dto.ProductListResponse;
import laughcandidate.yellowribbonbe.product.service.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "금융상품")
@RestController
@RequestMapping("/api/products")
@RequiredArgsConstructor
public class ProductController {

    private final ProductService productService;


    @GetMapping
    @Operation(
        summary = "금융상품 리스트 조회 API",
        description = "혜택 금융상품 리스트를 조회합니다.")
    public ResponseEntity<List<ProductListResponse>> getProducts(
            @RequestParam(required = false) String category,
            @AuthenticationPrincipal CustomUserDetails customUserDetails) {
        
        List<ProductListResponse> products = productService.getProducts(category);
        return ResponseEntity.ok(products);
    }
}
