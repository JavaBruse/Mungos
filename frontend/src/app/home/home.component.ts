import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './home.component.html',
  styleUrl: './home.component.scss'
})
export class HomeComponent implements OnInit {
  weather: any = null;
  currency: any = null;
  oil: any = null;

  constructor(private cdr: ChangeDetectorRef) { }

  ngOnInit() {
    // this.getWeather();
    // this.getFinanceData();
  }

  async getWeather() {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(async (pos) => {
        const { latitude, longitude } = pos.coords;
        const res = await fetch(`https://api.open-meteo.com/v1/forecast?latitude=${latitude}&longitude=${longitude}&current_weather=true`);
        this.weather = await res.json();
        this.cdr.detectChanges();
      });
    }
  }

  async getFinanceData() {
    try {
      // USD/RUB
      const resCurr = await fetch('https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/usd.json');
      const dataCurr = await resCurr.json();
      this.currency = dataCurr.usd.rub.toFixed(2);


      // const resOil = await fetch('https://rusoil.net/export/ajax.php?act=urals');
      // const oilData = await resOil.json();
      // this.oil = oilData.price;

      this.cdr.detectChanges();
    } catch (e) {
      console.error('Ошибка финансов:', e);
    }
  }
}