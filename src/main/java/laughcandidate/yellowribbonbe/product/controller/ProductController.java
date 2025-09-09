package laughcandidate.yellowribbonbe.product.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import laughcandidate.yellowribbonbe.auth.service.CustomUserDetails;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import laughcandidate.yellowribbonbe.product.dto.ProductDetailResponse;
import laughcandidate.yellowribbonbe.product.dto.ProductListResponse;
import laughcandidate.yellowribbonbe.product.service.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "금융상품")
@RestController
@RequestMapping("/products")
@RequiredArgsConstructor
public class ProductController {

    private final ProductService productService;


    @GetMapping
    @Operation(
        summary = "금융상품 리스트 조회 API",
        description = "혜택 금융상품 리스트를 조회합니다.")
    public ResponseEntity<ApiResponse<List<ProductListResponse>>> getProducts(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) Long badgeId,
            @AuthenticationPrincipal CustomUserDetails customUserDetails) {
        
        List<ProductListResponse> products = productService.getProducts(category, badgeId);
        return ResponseEntity.ok(ApiResponse.ok(products));
    }

    @GetMapping("/{productId}")
    @Operation(
        summary = "금융상품 상세 조회 API",
        description = "특정 금융상품의 상세 정보를 조회합니다.")
    public ResponseEntity<ApiResponse<ProductDetailResponse>> getProductDetail(
            @PathVariable Long productId,
            @AuthenticationPrincipal CustomUserDetails customUserDetails) {
        
        ProductDetailResponse productDetail = productService.getProductDetail(productId);
        return ResponseEntity.ok(ApiResponse.ok(productDetail));
    }
}
