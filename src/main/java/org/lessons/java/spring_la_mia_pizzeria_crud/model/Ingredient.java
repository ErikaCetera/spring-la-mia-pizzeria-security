package org.lessons.java.spring_la_mia_pizzeria_crud.model;

import java.math.BigDecimal;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;

@Entity
@Table(name = "ingredients")
public class Ingredient {
    

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @NotBlank(message = "must not be null, empty or blank")
    private String name;
    private String allergen;
    private BigDecimal price;


    @ManyToMany(mappedBy = "ingredients")
    @JsonIgnore
    private List<Pizza> pizze;


    
    public Integer getId() {
        return id;
    }
    public void setId(Integer id) {
        this.id = id;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public List<Pizza> getPizze() {
        return pizze;
    }
    public void setPizze(List<Pizza> pizze) {
        this.pizze = pizze;
    }
    public String getAllergen() {
        return allergen;
    }
    public void setAllergen(String allergen) {
        this.allergen = allergen;
    }
    public BigDecimal getPrice() {
        return price;
    }
    public void setPrice(BigDecimal price) {
        this.price = price;
    }

    
    
}
