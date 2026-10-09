import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping({"/api", "/v2"})
@PreAuthorize("isAuthenticated()")
class JobsController {
    @GetMapping("/jobs/{id}")
    String read(@PathVariable String id, @RequestParam(name="q", required=false) String filter) {
        return filter;
    }
    @RequestMapping(path="/jobs", method={RequestMethod.POST, RequestMethod.PUT})
    String save(@RequestBody String payload) { return payload; }
}
