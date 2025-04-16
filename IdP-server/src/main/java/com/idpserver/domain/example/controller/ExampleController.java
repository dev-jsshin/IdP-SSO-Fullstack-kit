package com.idpserver.domain.example.controller;

import com.idpserver.global.common.response.code.StatusCode;
import com.idpserver.global.common.response.dto.DataResponseDto;
import com.idpserver.global.common.response.exception.GeneralException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/example")
public class ExampleController {

    /*
     * success
     */
    @GetMapping(value = "")
    public String basic() throws Exception {
        return "success";
    }

    /*
     * success
     */
    @PostMapping(value = "")
    public String basic22() throws Exception {

        System.out.println("123123213123213");
        return "success";
    }

    /*
     *  "success": true,
     *  "code": 200,
     *  "message": "정상적으로 조회되었습니다."",
     *  "data": [
     *    1,
     *    2,
     *    3
     *  ]
     */
    @GetMapping(path = "/data")
    public DataResponseDto<Object> getDate() {
        return DataResponseDto.of(List.of(1, 2, 3));
    }

    /*
     *  "success": false,
     *  "code": 10001,
     *  "message": "Forced Error"
     */
    @GetMapping(path = "/error/custom")
    public DataResponseDto<Object> errorWithCustomException() {
        if (!false) {
            throw new GeneralException(StatusCode.VALIDATION_ERROR, "Forced Error");
        }

        return DataResponseDto.empty();
    }

    /*
     *  "success": false,
     *  "code": 20000,
     *  "message": "오류가 발생하였습니다. 관리자에게 문의바랍니다."
     */
    @GetMapping(path = "/error/handler")
    public DataResponseDto<Object> errorWithHandlerException() throws Exception {
        try {
            List<Integer> list = List.of(1, 2, 3, 4, 5, null);
        } catch (Exception e) {
            throw new Exception();
        }

        return DataResponseDto.empty();
    }
}
