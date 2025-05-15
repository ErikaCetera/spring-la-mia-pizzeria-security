package org.lessons.java.spring_la_mia_pizzeria_crud.controller;

import java.util.List;
import java.util.Optional;


import org.lessons.java.spring_la_mia_pizzeria_crud.model.Pizza;
import org.lessons.java.spring_la_mia_pizzeria_crud.service.PizzaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/adv/pizze")
public class PizzaAdvanceRestController {
    @Autowired
    private PizzaService pizzaService;

    @GetMapping
    public List<Pizza> Index() {
        List<Pizza> pizze = pizzaService.findAll();
        return pizze;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Pizza> show(@PathVariable Integer id) {
        Optional<Pizza> pizza = pizzaService.findById(id);
        if(pizza.isEmpty()){
            return new ResponseEntity<Pizza>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<Pizza>(pizza.get(), HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<Pizza> store(@RequestBody Pizza pizza) {
        return new ResponseEntity<Pizza>(pizzaService.create(pizza), HttpStatus.OK);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Pizza> update(@PathVariable Integer id, @RequestBody Pizza pizza) {
        if(pizzaService.findById(id).isEmpty()){
            return new ResponseEntity<Pizza>(HttpStatus.NOT_FOUND);
        }
        
        pizza.setId(id);
        return new ResponseEntity<Pizza>(pizzaService.update(pizza), HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Pizza> delete(@PathVariable Integer id){
        if(pizzaService.findById(id).isEmpty()){
            return new ResponseEntity<Pizza>(HttpStatus.NOT_FOUND);
        }
    pizzaService.deleteById(id);
    return new ResponseEntity<Pizza>(HttpStatus.NOT_FOUND);
    }
}
