package org.lessons.java.spring_la_mia_pizzeria_crud.model;

import java.time.LocalDate;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;


@Entity
@Table(name = "offers")
public class Offer {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    //l'altro lato, la pizza da cui dipende
    @ManyToOne
    @JoinColumn(name = "pizza_id", nullable = false)//chiave esterna
    private Pizza pizza;
    
    @NotNull(message = "non può essere null")
    private String title;
    @NotNull(message = "non può essere null")
    private LocalDate startOffer;
    private LocalDate endOffer;
    



    
    public Integer getId() {
        return id;
    }
    public void setId(Integer id) {
        this.id = id;
    }
    public Pizza getPizza() {
        return pizza;
    }
    public void setPizza(Pizza pizza) {
        this.pizza = pizza;
    }
    public LocalDate getStartOffer() {
        return startOffer;
    }
    public void setStartOffer(LocalDate startOffer) {
        this.startOffer = startOffer;
    }
    public LocalDate getEndOffer() {
        return endOffer;
    }
    public void setEndOffer(LocalDate endOffer) {
        this.endOffer = endOffer;
    }
    
    public String getTitle() {
        return title;
    }
    public void setTitle(String title) {
        this.title = title;
    }


    




}
