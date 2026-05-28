import { Component, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { DomSanitizer } from '@angular/platform-browser';
import { environment } from '../../environments/environment';

@Component({
  selector: 'app-leaderboard',
  template: `
    <div class="leaderboard">
      <h2>ðŸ† Leaderboard Global</h2>
      <!-- â† VULNERABLE: HTML del servidor sin sanitizar -->
      <div [innerHTML]="leaderboardHtml"></div>
      <table *ngIf="rankings.length">
        <tr><th>#</th><th>Jugador</th><th>Score</th><th>Nivel</th></tr>
        <tr *ngFor="let r of rankings; let i = index">
          <td>{{ i + 1 }}</td>
          <td>{{ r.nickname }}</td>
          <td>{{ r.score }}</td>
          <td>{{ r.level_reached }}</td>
        </tr>
      </table>
    </div>
  `
})
export class LeaderboardComponent implements OnInit {
  rankings: any[] = [];
  leaderboardHtml: any = '';

  constructor(private http: HttpClient, private sanitizer: DomSanitizer) {}

  ngOnInit() {
    // â† VULNERABLE: sin limite
    this.http.get<any>(`${environment.apiUrl}/leaderboard?limit=999999`)
      .subscribe(data => {
        this.rankings = data.rankings;
        // â† VULNERABLE: bypassea la seguridad de Angular
        if (data.html_banner) {
          this.leaderboardHtml = this.sanitizer.bypassSecurityTrustHtml(data.html_banner);
        }
      });
  }
}
