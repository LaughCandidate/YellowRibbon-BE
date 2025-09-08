package laughcandidate.yellowribbonbe.product.controller;

import laughcandidate.yellowribbonbe.product.dto.ProductListResponse;
import laughcandidate.yellowribbonbe.product.service.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/products")
@RequiredArgsConstructor
public class ProductController {

    private final ProductService productService;


    @GetMapping
    public ResponseEntity<List<ProductListResponse>> getProducts(
            @RequestParam(required = false) String category) {
        
        List<ProductListResponse> products = productService.getProducts(category);
        return ResponseEntity.ok(products);
    }
}
