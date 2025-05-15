package org.lessons.java.spring_la_mia_pizzeria_crud.controller;

import java.util.List;

import org.lessons.java.spring_la_mia_pizzeria_crud.model.Pizza;
import org.lessons.java.spring_la_mia_pizzeria_crud.service.PizzaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PutMapping;





@RestController
@RequestMapping("/api/pizze")
public class PizzaRestController {

    @Autowired
    private PizzaService pizzaService;

    @GetMapping
    public List<Pizza> Index() {
        List<Pizza> pizze = pizzaService.findAll();
        return pizze;
    }

    @GetMapping("/{id}")
    public Pizza show(@PathVariable Integer id) {
        Pizza pizza = pizzaService.getById(id);
        return pizza;
    }

    @PostMapping
    public Pizza store(@RequestBody Pizza pizza) {
        return pizzaService.create(pizza);
    }

    @PutMapping("/{id}")
    public Pizza update(@PathVariable Integer id, @RequestBody Pizza pizza) {
        pizza.setId(id);
        
        return pizzaService.update(pizza);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable Integer id){
    pizzaService.deleteById(id);
    }
    

}
